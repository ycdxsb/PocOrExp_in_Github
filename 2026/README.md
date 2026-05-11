## CVE-2026-44656
 Vim is an open source, command line text editor. Prior to version 9.2.0435, an OS command injection vulnerability exists in Vim's :find command-line completion. When the path option contains backtick-enclosed shell commands, those commands are executed during file name completion. Because the path option lacks the P_SECURE flag, it can be set from a modeline, allowing an attacker who controls the contents of a file to execute arbitrary shell commands when the user opens that file in Vim and triggers :find completion. This issue has been patched in version 9.2.0435.



- [https://github.com/CryingN/CVE-2026-44656](https://github.com/CryingN/CVE-2026-44656) :  ![starts](https://img.shields.io/github/stars/CryingN/CVE-2026-44656.svg) ![forks](https://img.shields.io/github/forks/CryingN/CVE-2026-44656.svg)

## CVE-2026-44109
 OpenClaw before 2026.4.15 contains an authentication bypass vulnerability in Feishu webhook and card-action validation that allows unauthenticated requests to reach command dispatch. Missing encryptKey configuration and blank callback tokens fail open instead of rejecting requests, enabling attackers to bypass signature verification and replay protection to execute arbitrary commands.



- [https://github.com/CryptReaper12/CVE-2026-44109](https://github.com/CryptReaper12/CVE-2026-44109) :  ![starts](https://img.shields.io/github/stars/CryptReaper12/CVE-2026-44109.svg) ![forks](https://img.shields.io/github/forks/CryptReaper12/CVE-2026-44109.svg)

## CVE-2026-43585
 OpenClaw before 2026.4.15 captures resolved bearer-auth configuration at startup, allowing revoked tokens to remain valid after SecretRef rotation. Gateway HTTP and WebSocket handlers fail to re-resolve authentication per-request, enabling attackers to use rotated-out bearer tokens for unauthorized gateway access.



- [https://github.com/ByteWraith1/CVE-2026-43585](https://github.com/ByteWraith1/CVE-2026-43585) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-43585.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-43585.svg)

## CVE-2026-43284
 In the Linux kernel, the following vulnerability has been resolved:

xfrm: esp: avoid in-place decrypt on shared skb frags

MSG_SPLICE_PAGES can attach pages from a pipe directly to an skb. TCP
marks such skbs with SKBFL_SHARED_FRAG after skb_splice_from_iter(),
so later paths that may modify packet data can first make a private
copy. The IPv4/IPv6 datagram append paths did not set this flag when
splicing pages into UDP skbs.

That leaves an ESP-in-UDP packet made from shared pipe pages looking
like an ordinary uncloned nonlinear skb. ESP input then takes the no-COW
fast path for uncloned skbs without a frag_list and decrypts in place
over data that is not owned privately by the skb.

Mark IPv4/IPv6 datagram splice frags with SKBFL_SHARED_FRAG, matching
TCP. Also make ESP input fall back to skb_cow_data() when the flag is
present, so ESP does not decrypt externally backed frags in place.
Private nonlinear skb frags still use the existing fast path.

This intentionally does not change ESP output. In esp_output_head(),
the path that appends the ESP trailer to existing skb tailroom without
calling skb_cow_data() is not reachable for nonlinear skbs:
skb_tailroom() returns zero when skb-data_len is nonzero, while ESP
tailen is positive. Thus ESP output will either use the separate
destination-frag path or fall back to skb_cow_data().



- [https://github.com/Percivalll/Dirty-Frag-Kubernetes-PoC](https://github.com/Percivalll/Dirty-Frag-Kubernetes-PoC) :  ![starts](https://img.shields.io/github/stars/Percivalll/Dirty-Frag-Kubernetes-PoC.svg) ![forks](https://img.shields.io/github/forks/Percivalll/Dirty-Frag-Kubernetes-PoC.svg)

- [https://github.com/infiniroot/ansible-mitigate-copyfail-dirtyfrag](https://github.com/infiniroot/ansible-mitigate-copyfail-dirtyfrag) :  ![starts](https://img.shields.io/github/stars/infiniroot/ansible-mitigate-copyfail-dirtyfrag.svg) ![forks](https://img.shields.io/github/forks/infiniroot/ansible-mitigate-copyfail-dirtyfrag.svg)

- [https://github.com/KaraZajac/DIRTYFAIL](https://github.com/KaraZajac/DIRTYFAIL) :  ![starts](https://img.shields.io/github/stars/KaraZajac/DIRTYFAIL.svg) ![forks](https://img.shields.io/github/forks/KaraZajac/DIRTYFAIL.svg)

- [https://github.com/haydenjames/dirty-frag-check](https://github.com/haydenjames/dirty-frag-check) :  ![starts](https://img.shields.io/github/stars/haydenjames/dirty-frag-check.svg) ![forks](https://img.shields.io/github/forks/haydenjames/dirty-frag-check.svg)

- [https://github.com/krisiasty/vcheck](https://github.com/krisiasty/vcheck) :  ![starts](https://img.shields.io/github/stars/krisiasty/vcheck.svg) ![forks](https://img.shields.io/github/forks/krisiasty/vcheck.svg)

- [https://github.com/0xBlackash/CVE-2026-43284](https://github.com/0xBlackash/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-43284.svg)

- [https://github.com/AK777177/Dirty-Frag-Analysis](https://github.com/AK777177/Dirty-Frag-Analysis) :  ![starts](https://img.shields.io/github/stars/AK777177/Dirty-Frag-Analysis.svg) ![forks](https://img.shields.io/github/forks/AK777177/Dirty-Frag-Analysis.svg)

- [https://github.com/linnemanlabs/dirtyfrag-arm64](https://github.com/linnemanlabs/dirtyfrag-arm64) :  ![starts](https://img.shields.io/github/stars/linnemanlabs/dirtyfrag-arm64.svg) ![forks](https://img.shields.io/github/forks/linnemanlabs/dirtyfrag-arm64.svg)

- [https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4](https://github.com/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4) :  ![starts](https://img.shields.io/github/stars/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4.svg) ![forks](https://img.shields.io/github/forks/mym0us3r/DIRTY-FRAG-Detection-with-Wazuh-4.14.4.svg)

- [https://github.com/dixyes/dirtypatch](https://github.com/dixyes/dirtypatch) :  ![starts](https://img.shields.io/github/stars/dixyes/dirtypatch.svg) ![forks](https://img.shields.io/github/forks/dixyes/dirtypatch.svg)

- [https://github.com/suominen/CVE-2026-43284](https://github.com/suominen/CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-43284.svg)

- [https://github.com/ryan2929/CVE-2026-43284-](https://github.com/ryan2929/CVE-2026-43284-) :  ![starts](https://img.shields.io/github/stars/ryan2929/CVE-2026-43284-.svg) ![forks](https://img.shields.io/github/forks/ryan2929/CVE-2026-43284-.svg)

- [https://github.com/scriptzteam/Paranoid-Dirty-Frag-CVE-2026-43284](https://github.com/scriptzteam/Paranoid-Dirty-Frag-CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/scriptzteam/Paranoid-Dirty-Frag-CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/scriptzteam/Paranoid-Dirty-Frag-CVE-2026-43284.svg)

- [https://github.com/attaattaatta/CVE-2026-43500](https://github.com/attaattaatta/CVE-2026-43500) :  ![starts](https://img.shields.io/github/stars/attaattaatta/CVE-2026-43500.svg) ![forks](https://img.shields.io/github/forks/attaattaatta/CVE-2026-43500.svg)

- [https://github.com/6abc/Copy-Fail-CVE-2026-31431-dirty-frag-CVE-2026-43284](https://github.com/6abc/Copy-Fail-CVE-2026-31431-dirty-frag-CVE-2026-43284) :  ![starts](https://img.shields.io/github/stars/6abc/Copy-Fail-CVE-2026-31431-dirty-frag-CVE-2026-43284.svg) ![forks](https://img.shields.io/github/forks/6abc/Copy-Fail-CVE-2026-31431-dirty-frag-CVE-2026-43284.svg)

- [https://github.com/metalx1993/dirtyfrag-patches](https://github.com/metalx1993/dirtyfrag-patches) :  ![starts](https://img.shields.io/github/stars/metalx1993/dirtyfrag-patches.svg) ![forks](https://img.shields.io/github/forks/metalx1993/dirtyfrag-patches.svg)

## CVE-2026-42796
 Arelle before 2.39.10 contains an unauthenticated remote code execution vulnerability in the /rest/configure REST endpoint that accepts a plugins query parameter and forwards it to the plugin manager without authentication or authorization. Attackers can supply a URL to a malicious Python file through the plugins parameter, causing the Arelle webserver to download and execute the attacker-controlled code within the Arelle process with its privileges.



- [https://github.com/ameerhamza-malik/CVE-2026-42796](https://github.com/ameerhamza-malik/CVE-2026-42796) :  ![starts](https://img.shields.io/github/stars/ameerhamza-malik/CVE-2026-42796.svg) ![forks](https://img.shields.io/github/forks/ameerhamza-malik/CVE-2026-42796.svg)

## CVE-2026-42779
 The fix for CVE-2026-41635 was not applied to the 2.1.X and 2.2.X branches. Here was the original issue description:











Apache MINA's AbstractIoBuffer.resolveClass() contains two branches, one of them (for static classes or primitive types) does not check the class at all, bypassing the classname allowlist and allowing arbitrary code to be executed.




The fix checks if the class is present in the accepted class filter before calling Class.forName(). 






Affected versions are Apache MINA 2.1.0 = 2.1.11, and 2.2.0 = 2.2.6.





The problem is resolved in Apache MINA 2.1.12, and 2.2.7 by 
applying the classname allowlist earlier.





Affected are applications using Apache MINA that call  IoBuffer.getObject().





Applications using Apache MINA are advised to upgrade.



- [https://github.com/dinosn/CVE-2026-42779](https://github.com/dinosn/CVE-2026-42779) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-42779.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-42779.svg)

## CVE-2026-42778
 The fix for CVE-2026-41409 was not applied to the 2.1.X and 2.2.X branches. Here was the original issue description:




The fix for CVE-2024-52046 in Apache MINA AbstractIoBuffer.getObject() was incomplete. The classname allowlist of classes allowed to be deserialized was applied too late after a static initializer in a class to be read might already have been executed.




Affected versions are Apache MINA 2.1.0 = 2.1.11, and 2.2.0 = 2.2.6.




The problem is resolved in Apache MINA 2.1.12, and 2.2.7 by 
applying the classname allowlist earlier.




Affected are applications using Apache MINA that call IoBuffer.getObject().




Applications using Apache MINA are advised to upgrade






The fix for CVE-2024-52046 in Apache MINA AbstractIoBuffer.getObject() was incomplete. The classname allowlist of classes allowed to be deserialized was applied too late after a static initializer in a class to be read might already have been executed.




Affected versions are Apache MINA 2.1.0 = 2.1.110, and 2.2.0 = 2.2.6.




The problem is resolved in Apache MINA 2.1.12, and 2.2.7 by 
applying the classname allowlist earlier.




Affected are applications using Apache MINA that call IoBuffer.getObject().




Applications using Apache MINA are advised to upgrade



- [https://github.com/Akinfue/CVE-2026-42778-POC](https://github.com/Akinfue/CVE-2026-42778-POC) :  ![starts](https://img.shields.io/github/stars/Akinfue/CVE-2026-42778-POC.svg) ![forks](https://img.shields.io/github/forks/Akinfue/CVE-2026-42778-POC.svg)

## CVE-2026-42231
 n8n is an open source workflow automation platform. Prior to versions 1.123.32, 2.17.4, and 2.18.1, a flaw in the xml2js library used to parse XML request bodies in n8n's webhook handler allowed prototype pollution via a crafted XML payload. An authenticated user with permission to create or modify workflows could exploit this to pollute the JavaScript object prototype and, by chaining the pollution with the Git node's SSH operations, achieve remote code execution on the n8n host. This issue has been patched in versions 1.123.32, 2.17.4, and 2.18.1.



- [https://github.com/rudSarkar/CVE-2026-42231](https://github.com/rudSarkar/CVE-2026-42231) :  ![starts](https://img.shields.io/github/stars/rudSarkar/CVE-2026-42231.svg) ![forks](https://img.shields.io/github/forks/rudSarkar/CVE-2026-42231.svg)

## CVE-2026-42228
 n8n is an open source workflow automation platform. Prior to versions 1.123.32, 2.17.4, and 2.18.1, the /chat WebSocket endpoint used by the Chat Trigger node's Hosted Chat feature did not verify that an incoming connection was authorized to interact with the target execution. An unauthenticated remote attacker who could identify a valid execution ID for a workflow in a waiting state could attach to that execution, receive the pending prompt intended for the legitimate user, and submit arbitrary input to resume or influence downstream workflow behavior. This issue has been patched in versions 1.123.32, 2.17.4, and 2.18.1.



- [https://github.com/rudSarkar/CVE-2026-42228](https://github.com/rudSarkar/CVE-2026-42228) :  ![starts](https://img.shields.io/github/stars/rudSarkar/CVE-2026-42228.svg) ![forks](https://img.shields.io/github/forks/rudSarkar/CVE-2026-42228.svg)

## CVE-2026-42208
 LiteLLM is a proxy server (AI Gateway) to call LLM APIs in OpenAI (or native) format. From version 1.81.16 to before version 1.83.7, a database query used during proxy API key checks mixed the caller-supplied key value into the query text instead of passing it as a separate parameter. An unauthenticated attacker could send a specially crafted Authorization header to any LLM API route (for example POST /chat/completions) and reach this query through the proxy's error-handling path. An attacker could read data from the proxy's database and may be able to modify it, leading to unauthorised access to the proxy and the credentials it manages. This issue has been patched in version 1.83.7.



- [https://github.com/imjdl/CVE-2026-42208_lab](https://github.com/imjdl/CVE-2026-42208_lab) :  ![starts](https://img.shields.io/github/stars/imjdl/CVE-2026-42208_lab.svg) ![forks](https://img.shields.io/github/forks/imjdl/CVE-2026-42208_lab.svg)

- [https://github.com/0xBlackash/CVE-2026-42208](https://github.com/0xBlackash/CVE-2026-42208) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-42208.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-42208.svg)

- [https://github.com/rootdirective-sec/cve-2026-42208-Lab](https://github.com/rootdirective-sec/cve-2026-42208-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/cve-2026-42208-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/cve-2026-42208-Lab.svg)

- [https://github.com/Zeltoc/threat-intel-brief-cve-2026-42208-litellm](https://github.com/Zeltoc/threat-intel-brief-cve-2026-42208-litellm) :  ![starts](https://img.shields.io/github/stars/Zeltoc/threat-intel-brief-cve-2026-42208-litellm.svg) ![forks](https://img.shields.io/github/forks/Zeltoc/threat-intel-brief-cve-2026-42208-litellm.svg)

## CVE-2026-42167
 mod_sql in ProFTPD before 1.3.9a allows remote attackers to execute arbitrary code via a username, in scenarios where there is logging of USER requests with an expansion such as %U, and the SQL backend allows commands (e.g., COPY TO PROGRAM).



- [https://github.com/ZeroPathAI/proftpd-CVE-2026-42167-poc](https://github.com/ZeroPathAI/proftpd-CVE-2026-42167-poc) :  ![starts](https://img.shields.io/github/stars/ZeroPathAI/proftpd-CVE-2026-42167-poc.svg) ![forks](https://img.shields.io/github/forks/ZeroPathAI/proftpd-CVE-2026-42167-poc.svg)

- [https://github.com/dinosn/proftpd-CVE-2026-42167-analysis](https://github.com/dinosn/proftpd-CVE-2026-42167-analysis) :  ![starts](https://img.shields.io/github/stars/dinosn/proftpd-CVE-2026-42167-analysis.svg) ![forks](https://img.shields.io/github/forks/dinosn/proftpd-CVE-2026-42167-analysis.svg)

- [https://github.com/kaleth4/CVE-2026-42167](https://github.com/kaleth4/CVE-2026-42167) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-42167.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-42167.svg)

- [https://github.com/efeanilarslan/CVE-2026-42167-Exploit](https://github.com/efeanilarslan/CVE-2026-42167-Exploit) :  ![starts](https://img.shields.io/github/stars/efeanilarslan/CVE-2026-42167-Exploit.svg) ![forks](https://img.shields.io/github/forks/efeanilarslan/CVE-2026-42167-Exploit.svg)

- [https://github.com/Sl4cK0TH/CVE-2026-42167-PoC](https://github.com/Sl4cK0TH/CVE-2026-42167-PoC) :  ![starts](https://img.shields.io/github/stars/Sl4cK0TH/CVE-2026-42167-PoC.svg) ![forks](https://img.shields.io/github/forks/Sl4cK0TH/CVE-2026-42167-PoC.svg)

- [https://github.com/jimmexploit/CVE-2026-42167-PoC](https://github.com/jimmexploit/CVE-2026-42167-PoC) :  ![starts](https://img.shields.io/github/stars/jimmexploit/CVE-2026-42167-PoC.svg) ![forks](https://img.shields.io/github/forks/jimmexploit/CVE-2026-42167-PoC.svg)

## CVE-2026-41940
 cPanel and WHM versions after 11.40 contain an authentication bypass vulnerability in the login flow that allows unauthenticated remote attackers to gain unauthorized access to the control panel.



- [https://github.com/ynsmroztas/cPanelSniper](https://github.com/ynsmroztas/cPanelSniper) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/cPanelSniper.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/cPanelSniper.svg)

- [https://github.com/assetnote/cpanel2shell-scanner](https://github.com/assetnote/cpanel2shell-scanner) :  ![starts](https://img.shields.io/github/stars/assetnote/cpanel2shell-scanner.svg) ![forks](https://img.shields.io/github/forks/assetnote/cpanel2shell-scanner.svg)

- [https://github.com/XsanFlip/poc-cpanel-cve-2026-41940](https://github.com/XsanFlip/poc-cpanel-cve-2026-41940) :  ![starts](https://img.shields.io/github/stars/XsanFlip/poc-cpanel-cve-2026-41940.svg) ![forks](https://img.shields.io/github/forks/XsanFlip/poc-cpanel-cve-2026-41940.svg)

- [https://github.com/adriyansyah-mf/cve-2026-41940-poc](https://github.com/adriyansyah-mf/cve-2026-41940-poc) :  ![starts](https://img.shields.io/github/stars/adriyansyah-mf/cve-2026-41940-poc.svg) ![forks](https://img.shields.io/github/forks/adriyansyah-mf/cve-2026-41940-poc.svg)

- [https://github.com/Sachinart/CVE-2026-41940-cpanel-0day](https://github.com/Sachinart/CVE-2026-41940-cpanel-0day) :  ![starts](https://img.shields.io/github/stars/Sachinart/CVE-2026-41940-cpanel-0day.svg) ![forks](https://img.shields.io/github/forks/Sachinart/CVE-2026-41940-cpanel-0day.svg)

- [https://github.com/bughunt4me/cpanelCVE-2026-41940](https://github.com/bughunt4me/cpanelCVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/bughunt4me/cpanelCVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/bughunt4me/cpanelCVE-2026-41940.svg)

- [https://github.com/ilmndwntr/CVE-2026-41940-MASS-EXPLOIT](https://github.com/ilmndwntr/CVE-2026-41940-MASS-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/ilmndwntr/CVE-2026-41940-MASS-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/ilmndwntr/CVE-2026-41940-MASS-EXPLOIT.svg)

- [https://github.com/rfxn/cpanel-sessionscribe](https://github.com/rfxn/cpanel-sessionscribe) :  ![starts](https://img.shields.io/github/stars/rfxn/cpanel-sessionscribe.svg) ![forks](https://img.shields.io/github/forks/rfxn/cpanel-sessionscribe.svg)

- [https://github.com/Kagantua/cPanelWHM-AuthBypass](https://github.com/Kagantua/cPanelWHM-AuthBypass) :  ![starts](https://img.shields.io/github/stars/Kagantua/cPanelWHM-AuthBypass.svg) ![forks](https://img.shields.io/github/forks/Kagantua/cPanelWHM-AuthBypass.svg)

- [https://github.com/debugactiveprocess/cPanel-WHM-AuthBypass-Session-Checker](https://github.com/debugactiveprocess/cPanel-WHM-AuthBypass-Session-Checker) :  ![starts](https://img.shields.io/github/stars/debugactiveprocess/cPanel-WHM-AuthBypass-Session-Checker.svg) ![forks](https://img.shields.io/github/forks/debugactiveprocess/cPanel-WHM-AuthBypass-Session-Checker.svg)

- [https://github.com/realawaisakbar/CVE-2026-41940-Exploit-PoC](https://github.com/realawaisakbar/CVE-2026-41940-Exploit-PoC) :  ![starts](https://img.shields.io/github/stars/realawaisakbar/CVE-2026-41940-Exploit-PoC.svg) ![forks](https://img.shields.io/github/forks/realawaisakbar/CVE-2026-41940-Exploit-PoC.svg)

- [https://github.com/senyx122/CVE-2026-41940](https://github.com/senyx122/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/senyx122/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/senyx122/CVE-2026-41940.svg)

- [https://github.com/shahidmallaofficial/cpanel-cve-2026-41940-fix](https://github.com/shahidmallaofficial/cpanel-cve-2026-41940-fix) :  ![starts](https://img.shields.io/github/stars/shahidmallaofficial/cpanel-cve-2026-41940-fix.svg) ![forks](https://img.shields.io/github/forks/shahidmallaofficial/cpanel-cve-2026-41940-fix.svg)

- [https://github.com/NULL200OK/cve-2026-41940-tool](https://github.com/NULL200OK/cve-2026-41940-tool) :  ![starts](https://img.shields.io/github/stars/NULL200OK/cve-2026-41940-tool.svg) ![forks](https://img.shields.io/github/forks/NULL200OK/cve-2026-41940-tool.svg)

- [https://github.com/Jenderal92/CVE-2026-41940](https://github.com/Jenderal92/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/Jenderal92/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/Jenderal92/CVE-2026-41940.svg)

- [https://github.com/Andrei-Dr/cpanel-cve-2026-41940-ioc](https://github.com/Andrei-Dr/cpanel-cve-2026-41940-ioc) :  ![starts](https://img.shields.io/github/stars/Andrei-Dr/cpanel-cve-2026-41940-ioc.svg) ![forks](https://img.shields.io/github/forks/Andrei-Dr/cpanel-cve-2026-41940-ioc.svg)

- [https://github.com/merdw/cPanel-CVE-2026-41940-Scanner](https://github.com/merdw/cPanel-CVE-2026-41940-Scanner) :  ![starts](https://img.shields.io/github/stars/merdw/cPanel-CVE-2026-41940-Scanner.svg) ![forks](https://img.shields.io/github/forks/merdw/cPanel-CVE-2026-41940-Scanner.svg)

- [https://github.com/AmirrezaMarzban/portscan-CVE-2026-41940](https://github.com/AmirrezaMarzban/portscan-CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/AmirrezaMarzban/portscan-CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/AmirrezaMarzban/portscan-CVE-2026-41940.svg)

- [https://github.com/Christian93111/CVE-2026-41940](https://github.com/Christian93111/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/Christian93111/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/Christian93111/CVE-2026-41940.svg)

- [https://github.com/Ap0dexMe0/CVE-2026-41940](https://github.com/Ap0dexMe0/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/Ap0dexMe0/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/Ap0dexMe0/CVE-2026-41940.svg)

- [https://github.com/MrOplus/CVE-2026-41940](https://github.com/MrOplus/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/MrOplus/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/MrOplus/CVE-2026-41940.svg)

- [https://github.com/mahfuzreham/cpanel-cve-2026-41940](https://github.com/mahfuzreham/cpanel-cve-2026-41940) :  ![starts](https://img.shields.io/github/stars/mahfuzreham/cpanel-cve-2026-41940.svg) ![forks](https://img.shields.io/github/forks/mahfuzreham/cpanel-cve-2026-41940.svg)

- [https://github.com/0xabdoulaye/CPANEL-CVE-2026-41940](https://github.com/0xabdoulaye/CPANEL-CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/0xabdoulaye/CPANEL-CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/0xabdoulaye/CPANEL-CVE-2026-41940.svg)

- [https://github.com/george1-adel/CVE-2026-41940_exploit](https://github.com/george1-adel/CVE-2026-41940_exploit) :  ![starts](https://img.shields.io/github/stars/george1-adel/CVE-2026-41940_exploit.svg) ![forks](https://img.shields.io/github/forks/george1-adel/CVE-2026-41940_exploit.svg)

- [https://github.com/zedxod/CVE-2026-41940-POC](https://github.com/zedxod/CVE-2026-41940-POC) :  ![starts](https://img.shields.io/github/stars/zedxod/CVE-2026-41940-POC.svg) ![forks](https://img.shields.io/github/forks/zedxod/CVE-2026-41940-POC.svg)

- [https://github.com/unteikyou/CVE-2026-41940-AuthBypass-Detector](https://github.com/unteikyou/CVE-2026-41940-AuthBypass-Detector) :  ![starts](https://img.shields.io/github/stars/unteikyou/CVE-2026-41940-AuthBypass-Detector.svg) ![forks](https://img.shields.io/github/forks/unteikyou/CVE-2026-41940-AuthBypass-Detector.svg)

- [https://github.com/kmaruthisrikar/CVE-2026-41940-cPanel-Auth-Bypass-Exploit](https://github.com/kmaruthisrikar/CVE-2026-41940-cPanel-Auth-Bypass-Exploit) :  ![starts](https://img.shields.io/github/stars/kmaruthisrikar/CVE-2026-41940-cPanel-Auth-Bypass-Exploit.svg) ![forks](https://img.shields.io/github/forks/kmaruthisrikar/CVE-2026-41940-cPanel-Auth-Bypass-Exploit.svg)

- [https://github.com/habibkaratas/sorry-ransomware-analysis](https://github.com/habibkaratas/sorry-ransomware-analysis) :  ![starts](https://img.shields.io/github/stars/habibkaratas/sorry-ransomware-analysis.svg) ![forks](https://img.shields.io/github/forks/habibkaratas/sorry-ransomware-analysis.svg)

- [https://github.com/YudaSamuel/cpanel-vuln-scanner](https://github.com/YudaSamuel/cpanel-vuln-scanner) :  ![starts](https://img.shields.io/github/stars/YudaSamuel/cpanel-vuln-scanner.svg) ![forks](https://img.shields.io/github/forks/YudaSamuel/cpanel-vuln-scanner.svg)

- [https://github.com/Wesuiliye/CVE-2026-41940](https://github.com/Wesuiliye/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/Wesuiliye/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/Wesuiliye/CVE-2026-41940.svg)

- [https://github.com/ZildanZ/CVE-2026-41940](https://github.com/ZildanZ/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/ZildanZ/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/ZildanZ/CVE-2026-41940.svg)

- [https://github.com/murrez/CVE-2026-41940](https://github.com/murrez/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-41940.svg)

- [https://github.com/Lutfifakee-Project/CVE-2026-41940](https://github.com/Lutfifakee-Project/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/Lutfifakee-Project/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/Lutfifakee-Project/CVE-2026-41940.svg)

- [https://github.com/0xF55/cve-2026-41940-exploit](https://github.com/0xF55/cve-2026-41940-exploit) :  ![starts](https://img.shields.io/github/stars/0xF55/cve-2026-41940-exploit.svg) ![forks](https://img.shields.io/github/forks/0xF55/cve-2026-41940-exploit.svg)

- [https://github.com/Unfold-Security/CVE-2026-41940-Detection](https://github.com/Unfold-Security/CVE-2026-41940-Detection) :  ![starts](https://img.shields.io/github/stars/Unfold-Security/CVE-2026-41940-Detection.svg) ![forks](https://img.shields.io/github/forks/Unfold-Security/CVE-2026-41940-Detection.svg)

- [https://github.com/linko-iheb/cve-2026-41940-scanner](https://github.com/linko-iheb/cve-2026-41940-scanner) :  ![starts](https://img.shields.io/github/stars/linko-iheb/cve-2026-41940-scanner.svg) ![forks](https://img.shields.io/github/forks/linko-iheb/cve-2026-41940-scanner.svg)

- [https://github.com/cy3erm/CVE-2026-41940-POC](https://github.com/cy3erm/CVE-2026-41940-POC) :  ![starts](https://img.shields.io/github/stars/cy3erm/CVE-2026-41940-POC.svg) ![forks](https://img.shields.io/github/forks/cy3erm/CVE-2026-41940-POC.svg)

- [https://github.com/0dev1337/cpanelscanner](https://github.com/0dev1337/cpanelscanner) :  ![starts](https://img.shields.io/github/stars/0dev1337/cpanelscanner.svg) ![forks](https://img.shields.io/github/forks/0dev1337/cpanelscanner.svg)

- [https://github.com/Ishanoshada/CVE-2026-41940-Exploit-PoC](https://github.com/Ishanoshada/CVE-2026-41940-Exploit-PoC) :  ![starts](https://img.shields.io/github/stars/Ishanoshada/CVE-2026-41940-Exploit-PoC.svg) ![forks](https://img.shields.io/github/forks/Ishanoshada/CVE-2026-41940-Exploit-PoC.svg)

- [https://github.com/MrAriaNet/cPanel-Fix](https://github.com/MrAriaNet/cPanel-Fix) :  ![starts](https://img.shields.io/github/stars/MrAriaNet/cPanel-Fix.svg) ![forks](https://img.shields.io/github/forks/MrAriaNet/cPanel-Fix.svg)

- [https://github.com/nickpaulsec/2026-41940-poc](https://github.com/nickpaulsec/2026-41940-poc) :  ![starts](https://img.shields.io/github/stars/nickpaulsec/2026-41940-poc.svg) ![forks](https://img.shields.io/github/forks/nickpaulsec/2026-41940-poc.svg)

- [https://github.com/sebinxavi/cve-checker-2026](https://github.com/sebinxavi/cve-checker-2026) :  ![starts](https://img.shields.io/github/stars/sebinxavi/cve-checker-2026.svg) ![forks](https://img.shields.io/github/forks/sebinxavi/cve-checker-2026.svg)

- [https://github.com/dennisec/CVE-2026-41940](https://github.com/dennisec/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/dennisec/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/dennisec/CVE-2026-41940.svg)

- [https://github.com/0xBlackash/CVE-2026-41940](https://github.com/0xBlackash/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-41940.svg)

- [https://github.com/OhmGun/whmxploit---CVE-2026-41940](https://github.com/OhmGun/whmxploit---CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/OhmGun/whmxploit---CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/OhmGun/whmxploit---CVE-2026-41940.svg)

- [https://github.com/devtint/CVE-2026-41940](https://github.com/devtint/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/devtint/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/devtint/CVE-2026-41940.svg)

- [https://github.com/thekawix/CVE-2026-41940](https://github.com/thekawix/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/thekawix/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/thekawix/CVE-2026-41940.svg)

- [https://github.com/itsismarcos/CVE-2026-41940](https://github.com/itsismarcos/CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/itsismarcos/CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/itsismarcos/CVE-2026-41940.svg)

- [https://github.com/rdyprtmx/poc-cve-2026-41940](https://github.com/rdyprtmx/poc-cve-2026-41940) :  ![starts](https://img.shields.io/github/stars/rdyprtmx/poc-cve-2026-41940.svg) ![forks](https://img.shields.io/github/forks/rdyprtmx/poc-cve-2026-41940.svg)

- [https://github.com/tahaXafous/CVE_2026_41940_scan_exploit](https://github.com/tahaXafous/CVE_2026_41940_scan_exploit) :  ![starts](https://img.shields.io/github/stars/tahaXafous/CVE_2026_41940_scan_exploit.svg) ![forks](https://img.shields.io/github/forks/tahaXafous/CVE_2026_41940_scan_exploit.svg)

- [https://github.com/tfawnies/CVE-2026-41940-next](https://github.com/tfawnies/CVE-2026-41940-next) :  ![starts](https://img.shields.io/github/stars/tfawnies/CVE-2026-41940-next.svg) ![forks](https://img.shields.io/github/forks/tfawnies/CVE-2026-41940-next.svg)

- [https://github.com/imbas007/POC_CVE-2026-41940](https://github.com/imbas007/POC_CVE-2026-41940) :  ![starts](https://img.shields.io/github/stars/imbas007/POC_CVE-2026-41940.svg) ![forks](https://img.shields.io/github/forks/imbas007/POC_CVE-2026-41940.svg)

- [https://github.com/iSee857/cPanel-WHM-CVE-2026-41940-AuthBypass](https://github.com/iSee857/cPanel-WHM-CVE-2026-41940-AuthBypass) :  ![starts](https://img.shields.io/github/stars/iSee857/cPanel-WHM-CVE-2026-41940-AuthBypass.svg) ![forks](https://img.shields.io/github/forks/iSee857/cPanel-WHM-CVE-2026-41940-AuthBypass.svg)

- [https://github.com/vineet7800/cpanel-malware-cleaner-cve-2026](https://github.com/vineet7800/cpanel-malware-cleaner-cve-2026) :  ![starts](https://img.shields.io/github/stars/vineet7800/cpanel-malware-cleaner-cve-2026.svg) ![forks](https://img.shields.io/github/forks/vineet7800/cpanel-malware-cleaner-cve-2026.svg)

- [https://github.com/Defacto-ridgepole254/CVE-2026-41940-Exploit-PoC](https://github.com/Defacto-ridgepole254/CVE-2026-41940-Exploit-PoC) :  ![starts](https://img.shields.io/github/stars/Defacto-ridgepole254/CVE-2026-41940-Exploit-PoC.svg) ![forks](https://img.shields.io/github/forks/Defacto-ridgepole254/CVE-2026-41940-Exploit-PoC.svg)

- [https://github.com/3tternp/CVE-2026-41940---cPanel-WHM-check](https://github.com/3tternp/CVE-2026-41940---cPanel-WHM-check) :  ![starts](https://img.shields.io/github/stars/3tternp/CVE-2026-41940---cPanel-WHM-check.svg) ![forks](https://img.shields.io/github/forks/3tternp/CVE-2026-41940---cPanel-WHM-check.svg)

- [https://github.com/sercanokur/CVE-2026-41940-cPanel-WHM-Verification-Tool](https://github.com/sercanokur/CVE-2026-41940-cPanel-WHM-Verification-Tool) :  ![starts](https://img.shields.io/github/stars/sercanokur/CVE-2026-41940-cPanel-WHM-Verification-Tool.svg) ![forks](https://img.shields.io/github/forks/sercanokur/CVE-2026-41940-cPanel-WHM-Verification-Tool.svg)

- [https://github.com/44pie/cpsniper](https://github.com/44pie/cpsniper) :  ![starts](https://img.shields.io/github/stars/44pie/cpsniper.svg) ![forks](https://img.shields.io/github/forks/44pie/cpsniper.svg)

- [https://github.com/Underh0st/CPanel-Audit-Remediation-Tool](https://github.com/Underh0st/CPanel-Audit-Remediation-Tool) :  ![starts](https://img.shields.io/github/stars/Underh0st/CPanel-Audit-Remediation-Tool.svg) ![forks](https://img.shields.io/github/forks/Underh0st/CPanel-Audit-Remediation-Tool.svg)

- [https://github.com/Richflexpix/cpanel-pwn](https://github.com/Richflexpix/cpanel-pwn) :  ![starts](https://img.shields.io/github/stars/Richflexpix/cpanel-pwn.svg) ![forks](https://img.shields.io/github/forks/Richflexpix/cpanel-pwn.svg)

- [https://github.com/branixsolutions/Security-CVE-2026-41940-cPanel-WHM-WP2](https://github.com/branixsolutions/Security-CVE-2026-41940-cPanel-WHM-WP2) :  ![starts](https://img.shields.io/github/stars/branixsolutions/Security-CVE-2026-41940-cPanel-WHM-WP2.svg) ![forks](https://img.shields.io/github/forks/branixsolutions/Security-CVE-2026-41940-cPanel-WHM-WP2.svg)

- [https://github.com/ngksiva/cpanel-forensics](https://github.com/ngksiva/cpanel-forensics) :  ![starts](https://img.shields.io/github/stars/ngksiva/cpanel-forensics.svg) ![forks](https://img.shields.io/github/forks/ngksiva/cpanel-forensics.svg)

- [https://github.com/acuciureanu/cpanel2shell-honeypot](https://github.com/acuciureanu/cpanel2shell-honeypot) :  ![starts](https://img.shields.io/github/stars/acuciureanu/cpanel2shell-honeypot.svg) ![forks](https://img.shields.io/github/forks/acuciureanu/cpanel2shell-honeypot.svg)

- [https://github.com/SreejaPuthan/cpanel-control-plane-exposure-check](https://github.com/SreejaPuthan/cpanel-control-plane-exposure-check) :  ![starts](https://img.shields.io/github/stars/SreejaPuthan/cpanel-control-plane-exposure-check.svg) ![forks](https://img.shields.io/github/forks/SreejaPuthan/cpanel-control-plane-exposure-check.svg)

## CVE-2026-41900
 OpenLearnX is an open-source, decentralized learning and assessment platform. Prior to version 2.0.3, a remote code execution (RCE) vulnerability was identified in the OpenLearnX code execution environment, allowing sandbox escape and arbitrary command execution. This issue has been patched in version 2.0.3.



- [https://github.com/Christbowel/CVE-2026-41900-POC](https://github.com/Christbowel/CVE-2026-41900-POC) :  ![starts](https://img.shields.io/github/stars/Christbowel/CVE-2026-41900-POC.svg) ![forks](https://img.shields.io/github/forks/Christbowel/CVE-2026-41900-POC.svg)

## CVE-2026-41679
 Paperclip is a Node.js server and React UI that orchestrates a team of AI agents to run a business. Prior to version 2026.416.0, an unauthenticated attacker can achieve full remote code execution on any network-accessible Paperclip instance running in `authenticated` mode with default configuration. No user interaction, no credentials, just the target's address. The chain consists of six API calls. The attack is fully automated, requires no user interaction, and works against the default deployment configuration. Version 2026.416.0 patches the issue.



- [https://github.com/bartfroklage/cve-2026-41679](https://github.com/bartfroklage/cve-2026-41679) :  ![starts](https://img.shields.io/github/stars/bartfroklage/cve-2026-41679.svg) ![forks](https://img.shields.io/github/forks/bartfroklage/cve-2026-41679.svg)

## CVE-2026-41653
 BentoPDF is a client-side PDF toolkit that is self hostable. Prior to version 2.8.3, a cross-site scripting vulnerability was identified in BentoPD. An attacker may be able to execute arbitrary JavaScript in certain circumstances in Markdown to PDF Tool. This issue has been patched in version 2.8.3.



- [https://github.com/Astaruf/CVE-2026-41653](https://github.com/Astaruf/CVE-2026-41653) :  ![starts](https://img.shields.io/github/stars/Astaruf/CVE-2026-41653.svg) ![forks](https://img.shields.io/github/forks/Astaruf/CVE-2026-41653.svg)

## CVE-2026-41651
 PackageKit is a a D-Bus abstraction layer that allows the user to manage packages in a secure way using a cross-distro, cross-architecture API. PackageKit between and including versions 1.0.2 and 1.3.4 is vulnerable to a time-of-check time-of-use (TOCTOU) race condition on transaction flags that allows unprivileged users to install packages as root and thus leads to a local privilege escalation. This is patched in version 1.3.5.

A local unprivileged user can install arbitrary RPM packages as root, including executing RPM scriptlets, without authentication. The vulnerability is a TOCTOU race condition on `transaction-cached_transaction_flags`  combined with a silent state-machine guard that discards illegal backward transitions while leaving corrupted flags in place. Three bugs exist in `src/pk-transaction.c`:
1. Unconditional flag overwrite (line 4036): `InstallFiles()` writes caller-supplied flags to `transaction-cached_transaction_flags` without checking whether the transaction has already been  authorized/started. A second call blindly overwrites the flags even while the transaction is RUNNING.
2. Silent state-transition rejection (lines 873–882): `pk_transaction_set_state()` silently discards backward state transitions (e.g. `RUNNING` → `WAITING_FOR_AUTH`) but the flag overwrite at step 1 already happened. The transaction continues running with corrupted flags.
3. Late flag read at execution time (lines 2273–2277): The scheduler's idle callback reads cached_transaction_flags at dispatch time, not at authorization time. If flags were overwritten between authorization and execution, the backend sees the attacker's flags.



- [https://github.com/Vozec/CVE-2026-41651](https://github.com/Vozec/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/Vozec/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/Vozec/CVE-2026-41651.svg)

- [https://github.com/CipherCloak/CVE-2026-41651](https://github.com/CipherCloak/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/CipherCloak/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/CipherCloak/CVE-2026-41651.svg)

- [https://github.com/baph00met/CVE-2026-41651](https://github.com/baph00met/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/baph00met/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/baph00met/CVE-2026-41651.svg)

- [https://github.com/0xBlackash/CVE-2026-41651](https://github.com/0xBlackash/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-41651.svg)

- [https://github.com/dinosn/pack2theroot-lab](https://github.com/dinosn/pack2theroot-lab) :  ![starts](https://img.shields.io/github/stars/dinosn/pack2theroot-lab.svg) ![forks](https://img.shields.io/github/forks/dinosn/pack2theroot-lab.svg)

- [https://github.com/mawussid/CVE-2026-41651-Python](https://github.com/mawussid/CVE-2026-41651-Python) :  ![starts](https://img.shields.io/github/stars/mawussid/CVE-2026-41651-Python.svg) ![forks](https://img.shields.io/github/forks/mawussid/CVE-2026-41651-Python.svg)

- [https://github.com/aexdyhaxor/CVE-2026-41651](https://github.com/aexdyhaxor/CVE-2026-41651) :  ![starts](https://img.shields.io/github/stars/aexdyhaxor/CVE-2026-41651.svg) ![forks](https://img.shields.io/github/forks/aexdyhaxor/CVE-2026-41651.svg)

- [https://github.com/Kowntaewook/CVE-2026-41651-analysis](https://github.com/Kowntaewook/CVE-2026-41651-analysis) :  ![starts](https://img.shields.io/github/stars/Kowntaewook/CVE-2026-41651-analysis.svg) ![forks](https://img.shields.io/github/forks/Kowntaewook/CVE-2026-41651-analysis.svg)

- [https://github.com/shibaaa204/Pack2TheRoot](https://github.com/shibaaa204/Pack2TheRoot) :  ![starts](https://img.shields.io/github/stars/shibaaa204/Pack2TheRoot.svg) ![forks](https://img.shields.io/github/forks/shibaaa204/Pack2TheRoot.svg)

- [https://github.com/mazofeifaalfaro/check_pack2theroot](https://github.com/mazofeifaalfaro/check_pack2theroot) :  ![starts](https://img.shields.io/github/stars/mazofeifaalfaro/check_pack2theroot.svg) ![forks](https://img.shields.io/github/forks/mazofeifaalfaro/check_pack2theroot.svg)

## CVE-2026-41575
 In th30d4y/IP from version 1.0.1 to before version 2.0.1, a DOM-Based Cross-Site Scripting (XSS) vulnerability was identified in an IP Reputation Checker application. Unsanitized user input was directly rendered in the browser, allowing attackers to execute arbitrary JavaScript. This issue has been patched in version 2.0.1.



- [https://github.com/krrazee/CVE-2026-41575](https://github.com/krrazee/CVE-2026-41575) :  ![starts](https://img.shields.io/github/stars/krrazee/CVE-2026-41575.svg) ![forks](https://img.shields.io/github/forks/krrazee/CVE-2026-41575.svg)

## CVE-2026-41462
 ProjeQtor versions 7.0 through 12.4.3 contain an unauthenticated SQL injection vulnerability in the login functionality where the login variable is directly concatenated into a SQL query without parameterization or sanitization. Attackers can inject arbitrary SQL expressions through the username field at the authentication endpoint to create privileged accounts, read sensitive data, and execute operating system commands if the database user has elevated permissions.



- [https://github.com/0xBlackash/CVE-2026-41462](https://github.com/0xBlackash/CVE-2026-41462) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-41462.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-41462.svg)

## CVE-2026-41303
 OpenClaw before 2026.3.28 contains an authorization bypass vulnerability in Discord text approval commands that allows non-approvers to resolve pending exec approvals. Attackers can send Discord text commands to bypass the channels.discord.execApprovals.approvers allowlist and approve pending host execution requests.



- [https://github.com/kaleth4/CVE-2026-41303](https://github.com/kaleth4/CVE-2026-41303) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-41303.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-41303.svg)

## CVE-2026-41285
 In OpenBSD through 7.8, the slaacd and rad daemons have an infinite loop when they receive a crafted ICMPv6 Neighbor Discovery (ND) option (over a local network) with length zero, because of an "nd_opt_len * 8 - 2" expression with no preceding check for whether nd_opt_len is zero.



- [https://github.com/Rat5ak/CVE-2026-41285-OpenBSD-v6daemons-go-brrr](https://github.com/Rat5ak/CVE-2026-41285-OpenBSD-v6daemons-go-brrr) :  ![starts](https://img.shields.io/github/stars/Rat5ak/CVE-2026-41285-OpenBSD-v6daemons-go-brrr.svg) ![forks](https://img.shields.io/github/forks/Rat5ak/CVE-2026-41285-OpenBSD-v6daemons-go-brrr.svg)

## CVE-2026-41242
 protobufjs compiles protobuf definitions into JavaScript (JS) functions. In versions prior to 8.0.1 and 7.5.5, attackers can inject arbitrary code in the "type" fields of protobuf definitions, which will then execute during object decoding using that definition. Versions 8.0.1 and 7.5.5 patch the issue.



- [https://github.com/4chech/CVE-2026-41242](https://github.com/4chech/CVE-2026-41242) :  ![starts](https://img.shields.io/github/stars/4chech/CVE-2026-41242.svg) ![forks](https://img.shields.io/github/forks/4chech/CVE-2026-41242.svg)

## CVE-2026-41200
 STIG Manager is an API and web client for managing  Security Technical Implementation Guides (STIG) assessments of Information Systems. Versions 1.5.10 through 1.6.7 have a reflected Cross-Site Scripting (XSS) vulnerability in the OIDC authentication error handling code in `src/init.js` and `public/reauth.html`. During the OIDC redirect flow, the `error` and `error_description` query parameters returned by the OIDC provider are written directly to the DOM via `innerHTML` without HTML escaping. An attacker who can craft a malicious redirect URL and convince a user to follow it can execute arbitrary JavaScript in the application's origin context. The vulnerability is most severe when the targeted user has an active STIG Manager session running in another browser tab — injected code executes in the same origin and can communicate with the SharedWorker managing the active access token, enabling authenticated API requests on behalf of the victim including reading and modifying collection data. The vulnerability is patched in version 1.6.8. There is no workaround short of upgrading. Deployments behind a web application firewall that filters reflected XSS payloads in query parameters may have partial mitigation, but this is not a substitute for patching.



- [https://github.com/Hunt-Benito/cve-2026-41200-stig-manager-oidc-reflected-xss](https://github.com/Hunt-Benito/cve-2026-41200-stig-manager-oidc-reflected-xss) :  ![starts](https://img.shields.io/github/stars/Hunt-Benito/cve-2026-41200-stig-manager-oidc-reflected-xss.svg) ![forks](https://img.shields.io/github/forks/Hunt-Benito/cve-2026-41200-stig-manager-oidc-reflected-xss.svg)

## CVE-2026-41177
 Squidex is an open source headless content management system and content management hub. Prior to version 7.23.0, the Squidex Restore API is vulnerable to Blind Server-Side Request Forgery (SSRF). The application fails to validate the URI scheme of the user-supplied `Url` parameter, allowing the use of the `file://` protocol. This allows an authenticated administrator to force the backend server to interact with the local filesystem, which can lead to Local File Interaction (LFI) and potential disclosure of sensitive system information through side-channel analysis of internal logs. Version 7.23.0 contains a fix.



- [https://github.com/TurkiOS/CVE-2026-41177-Squidex-CMS](https://github.com/TurkiOS/CVE-2026-41177-Squidex-CMS) :  ![starts](https://img.shields.io/github/stars/TurkiOS/CVE-2026-41177-Squidex-CMS.svg) ![forks](https://img.shields.io/github/forks/TurkiOS/CVE-2026-41177-Squidex-CMS.svg)

## CVE-2026-41044
 Improper Input Validation, Improper Control of Generation of Code ('Code Injection') vulnerability in Apache ActiveMQ, Apache ActiveMQ Broker, Apache ActiveMQ All.

An authenticated attacker can use the admin web console page to construct a malicious broker name that bypasses name validation to include an xbean binding that can be later used by a VM transport to load a remote Spring XML application.
The attacker can then use the DestinationView mbean to send a message to trigger a VM transport creation that will reference this malicious broker name which can lead to loading the malicious Spring XML context file.


Because Spring's ResourceXmlApplicationContext instantiates all singleton beans before the BrokerService validates the configuration, arbitrary code execution occurs on the broker's JVM through bean factory methods such as Runtime.exec().

This issue affects Apache ActiveMQ: before 5.19.6, from 6.0.0 before 6.2.5; Apache ActiveMQ Broker: before 5.19.6, from 6.0.0 before 6.2.5; Apache ActiveMQ All: before 5.19.6, from 6.0.0 before 6.2.5.

Users are recommended to upgrade to version 6.2.5 or 5.19.6, which fixes the issue.



- [https://github.com/mrillicit/CVE-2026-41044](https://github.com/mrillicit/CVE-2026-41044) :  ![starts](https://img.shields.io/github/stars/mrillicit/CVE-2026-41044.svg) ![forks](https://img.shields.io/github/forks/mrillicit/CVE-2026-41044.svg)

## CVE-2026-40897
 Math.js is an extensive math library for JavaScript and Node.js. From 13.1.1 to before 15.2.0, a vulnerability allowed executing arbitrary JavaScript via the expression parser of mathjs. You can be affected when you have an application where users can evaluate arbitrary expressions using the mathjs expression parser. This vulnerability is fixed in 15.2.0.



- [https://github.com/EQSTLab/CVE-2026-40897](https://github.com/EQSTLab/CVE-2026-40897) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-40897.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-40897.svg)

## CVE-2026-40858
 The camel-infinispan component's ProtoStream-based remote aggregation repository deserializes data read from a remote Infinispan cache using java.io.ObjectInputStream without applying any ObjectInputFilter. An attacker who can write to the Infinispan cache used by a Camel application can inject a crafted serialized Java object that, when read during normal aggregation repository operations such as get or recover, results in arbitrary code execution in the context of the application.

This issue affects Apache Camel: from 4.0.0 before 4.14.7, from 4.15.0 before 4.18.2, from 4.19.0 before 4.20.0.

Users are recommended to upgrade to version 4.20.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.7. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.2.

The JIRA ticket:  https://issues.apache.org/jira/browse/CAMEL-23322  refers to the various commits that resolved the issue, and have more details. This issue follows the same class of vulnerability previously addressed in CVE-2024-22369, CVE-2024-23114 and CVE-2026-25747.



- [https://github.com/dinosn/CVE-2026-33453](https://github.com/dinosn/CVE-2026-33453) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-33453.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-33453.svg)

## CVE-2026-40487
 Postiz is an AI social media scheduling tool. Prior to version 2.21.6, a file upload validation bypass allows any authenticated user to upload arbitrary HTML, SVG, or other executable file types to the server by spoofing the `Content-Type` header. The uploaded files are then served by nginx with a Content-Type derived from their original extension (`text/html`, `image/svg+xml`), enabling Stored Cross-Site Scripting (XSS) in the context of the application's origin. This can lead to session riding, account takeover, and full compromise of other users' accounts. Version 2.21.6 contains a fix.



- [https://github.com/Astaruf/CVE-2026-40487](https://github.com/Astaruf/CVE-2026-40487) :  ![starts](https://img.shields.io/github/stars/Astaruf/CVE-2026-40487.svg) ![forks](https://img.shields.io/github/forks/Astaruf/CVE-2026-40487.svg)

- [https://github.com/0xBlackash/CVE-2026-42208](https://github.com/0xBlackash/CVE-2026-42208) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-42208.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-42208.svg)

## CVE-2026-40478
 Thymeleaf is a server-side Java template engine for web and standalone environments. Versions 3.1.3.RELEASE and prior contain a security bypass vulnerability in the the expression execution mechanisms. Although the library provides mechanisms to prevent expression injection, it fails to properly neutralize specific syntax patterns that allow for the execution of unauthorized expressions. If an application developer passes unvalidated user input directly to the template engine, an unauthenticated remote attacker can bypass the library's protections to achieve Server-Side Template Injection (SSTI). This issue has ben fixed in version 3.1.4.RELEASE.



- [https://github.com/bmvermeer/thymeleaf.CVE_2026_40478](https://github.com/bmvermeer/thymeleaf.CVE_2026_40478) :  ![starts](https://img.shields.io/github/stars/bmvermeer/thymeleaf.CVE_2026_40478.svg) ![forks](https://img.shields.io/github/forks/bmvermeer/thymeleaf.CVE_2026_40478.svg)

## CVE-2026-40473
 The camel-mina component's MinaConverter.toObjectInput(IoBuffer) type converter wraps an IoBuffer in a java.io.ObjectInputStream without applying any ObjectInputFilter or class-loading restrictions. When a Camel route uses camel-mina as a TCP or UDP consumer and requests conversion to ObjectInput (for example via getBody(ObjectInput.class) or @Body ObjectInput), an attacker sending a crafted serialized Java object over the network to the MINA consumer port can trigger arbitrary code execution in the context of the application during readObject().

This issue affects Apache Camel: from 3.0.0 before 4.14.6, from 4.15.0 before 4.18.2, from 4.19.0 before 4.20.0.

Users are recommended to upgrade to version 4.20.0, which fixes the issue. If users are on the 4.14.x LTS releases stream, then they are suggested to upgrade to 4.14.6. If users are on the 4.18.x releases stream, then they are suggested to upgrade to 4.18.2.



- [https://github.com/dinosn/CVE-2026-33453](https://github.com/dinosn/CVE-2026-33453) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-33453.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-33453.svg)

## CVE-2026-40466
 Improper Input Validation, Improper Control of Generation of Code ('Code Injection') vulnerability in Apache ActiveMQ Broker, Apache ActiveMQ All, Apache ActiveMQ.



An authenticated attacker may bypass the fix in CVE-2026-34197 by adding a connector using an HTTP Discovery transport via BrokerView.addNetworkConnector or BrokerView.addConnector through Jolokia if the activemq-http module is on the classpath.
A malicious HTTP endpoint can return a VM transport through the HTTP URI which will bypass the validation added in CVE-2026-34197. The attacker can then use the VM transport's brokerConfig parameter to load a remote Spring XML application context using ResourceXmlApplicationContext.
Because Spring's ResourceXmlApplicationContext instantiates all singleton beans before the BrokerService validates the configuration, arbitrary code execution occurs on the broker's JVM through bean factory methods such as Runtime.exec().


This issue affects Apache ActiveMQ Broker: before 5.19.6, from 6.0.0 before 6.2.5; Apache ActiveMQ All: before 5.19.6, from 6.0.0 before 6.2.5; Apache ActiveMQ: before 5.19.6, from 6.0.0 before 6.2.5.

Users are recommended to upgrade to version 5.19.6 or 6.2.5, which fixes the issue.



- [https://github.com/Catherines77/ActiveMQ-EXPtools](https://github.com/Catherines77/ActiveMQ-EXPtools) :  ![starts](https://img.shields.io/github/stars/Catherines77/ActiveMQ-EXPtools.svg) ![forks](https://img.shields.io/github/forks/Catherines77/ActiveMQ-EXPtools.svg)

## CVE-2026-40281
 Gotenberg is a Docker-powered stateless API for PDF files. In versions 8.30.1 and earlier, the metadata write endpoint validates metadata keys for control characters but leaves metadata values unsanitized. A newline character in a metadata value splits the ExifTool stdin line into two separate arguments, allowing injection of arbitrary ExifTool pseudo-tags such as -FileName, -Directory, -SymLink, and -HardLink. This is a bypass of the incomplete key-sanitization fix introduced in v8.30.1. An unauthenticated attacker can rename or move any PDF being processed to an arbitrary path in the container filesystem, overwrite arbitrary files, or create symlinks and hard links at arbitrary paths.



- [https://github.com/ByteWraith1/CVE-2026-40281](https://github.com/ByteWraith1/CVE-2026-40281) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-40281.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-40281.svg)

## CVE-2026-40261
 Composer is a dependency manager for PHP. Versions 1.0 through 2.2.26 and 2.3 through 2.9.5 contain a command injection vulnerability in the Perforce::syncCodeBase() method, which appends the $sourceReference parameter to a shell command without proper escaping, and additionally in the Perforce::generateP4Command() method as in GHSA-wg36-wvj6-r67p / CVE-2026-40176, which interpolates user-supplied Perforce connection parameters (port, user, client) from the source url field without proper escaping. An attacker can inject arbitrary commands through crafted source reference or source url values containing shell metacharacters, even if Perforce is not installed. Unlike CVE-2026-40176, the source reference and url are provided as part of package metadata, meaning any compromised or malicious Composer repository can serve package metadata declaring perforce as a source type with malicious values. This vulnerability is exploitable when installing or updating dependencies from source, including the default behavior when installing dev-prefixed versions. This issue has been fixed in Composer 2.2.27 (2.2 LTS) and 2.9.6 (mainline). If developers are unable to immediately update, they can avoid installing dependencies from source by using --prefer-dist or the preferred-install: dist config setting, and only use trusted Composer repositories as a workaround.



- [https://github.com/terminat0r7031/composer-CVE-2026-40261-CVE-2026-40176-PoC](https://github.com/terminat0r7031/composer-CVE-2026-40261-CVE-2026-40176-PoC) :  ![starts](https://img.shields.io/github/stars/terminat0r7031/composer-CVE-2026-40261-CVE-2026-40176-PoC.svg) ![forks](https://img.shields.io/github/forks/terminat0r7031/composer-CVE-2026-40261-CVE-2026-40176-PoC.svg)

- [https://github.com/daptheHuman/cve-2026-40176-cve-2026-40261](https://github.com/daptheHuman/cve-2026-40176-cve-2026-40261) :  ![starts](https://img.shields.io/github/stars/daptheHuman/cve-2026-40176-cve-2026-40261.svg) ![forks](https://img.shields.io/github/forks/daptheHuman/cve-2026-40176-cve-2026-40261.svg)

## CVE-2026-40176
 Composer is a dependency manager for PHP. Versions 1.0 through 2.2.26 and 2.3 through 2.9.5 contain a command injection vulnerability in the Perforce::generateP4Command() method, which constructs shell commands by interpolating user-supplied Perforce connection parameters (port, user, client) without proper escaping. An attacker can inject arbitrary commands through these values in a malicious composer.json declaring a Perforce VCS repository, leading to command execution in the context of the user running Composer, even if Perforce is not installed. VCS repositories are only loaded from the root composer.json or the composer config directory, so this cannot be exploited through composer.json files of packages installed as dependencies. Users are at risk if they run Composer commands on untrusted projects with attacker-supplied composer.json files. This issue has been fixed in Composer 2.2.27 (2.2 LTS) and 2.9.6 (mainline).



- [https://github.com/Saku0512/CVE-2026-40176-poc](https://github.com/Saku0512/CVE-2026-40176-poc) :  ![starts](https://img.shields.io/github/stars/Saku0512/CVE-2026-40176-poc.svg) ![forks](https://img.shields.io/github/forks/Saku0512/CVE-2026-40176-poc.svg)

- [https://github.com/terminat0r7031/composer-CVE-2026-40261-CVE-2026-40176-PoC](https://github.com/terminat0r7031/composer-CVE-2026-40261-CVE-2026-40176-PoC) :  ![starts](https://img.shields.io/github/stars/terminat0r7031/composer-CVE-2026-40261-CVE-2026-40176-PoC.svg) ![forks](https://img.shields.io/github/forks/terminat0r7031/composer-CVE-2026-40261-CVE-2026-40176-PoC.svg)

- [https://github.com/daptheHuman/cve-2026-40176-cve-2026-40261](https://github.com/daptheHuman/cve-2026-40176-cve-2026-40261) :  ![starts](https://img.shields.io/github/stars/daptheHuman/cve-2026-40176-cve-2026-40261.svg) ![forks](https://img.shields.io/github/forks/daptheHuman/cve-2026-40176-cve-2026-40261.svg)

## CVE-2026-40175
 Axios is a promise based HTTP client for the browser and Node.js. Prior to 1.15.0 and 0.3.1, the Axios library is vulnerable to a specific "Gadget" attack chain that allows Prototype Pollution in any third-party dependency to be escalated into Remote Code Execution (RCE) or Full Cloud Compromise (via AWS IMDSv2 bypass). This vulnerability is fixed in 1.15.0 and 0.3.1.



- [https://github.com/0xBlackash/CVE-2026-40175](https://github.com/0xBlackash/CVE-2026-40175) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-40175.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-40175.svg)

- [https://github.com/pjt3591oo/CVE-2026-40175-poc](https://github.com/pjt3591oo/CVE-2026-40175-poc) :  ![starts](https://img.shields.io/github/stars/pjt3591oo/CVE-2026-40175-poc.svg) ![forks](https://img.shields.io/github/forks/pjt3591oo/CVE-2026-40175-poc.svg)

- [https://github.com/surri/audit-axios](https://github.com/surri/audit-axios) :  ![starts](https://img.shields.io/github/stars/surri/audit-axios.svg) ![forks](https://img.shields.io/github/forks/surri/audit-axios.svg)

- [https://github.com/LeeKangHyun/axios-security-guide](https://github.com/LeeKangHyun/axios-security-guide) :  ![starts](https://img.shields.io/github/stars/LeeKangHyun/axios-security-guide.svg) ![forks](https://img.shields.io/github/forks/LeeKangHyun/axios-security-guide.svg)

## CVE-2026-40003
 ZTE ZX297520V3 BootROM contains a vulnerability that allows arbitrary memory writes via USB. Attackers can exploit the lack of target address validation in the USB download mode to write data to any location in BootROM runtime memory, thereby overwriting the stack, hijacking the execution flow, bypassing the Secure Boot signature verification mechanism, and achieving unauthorized code execution.



- [https://github.com/rva3/CVE-2026-40003](https://github.com/rva3/CVE-2026-40003) :  ![starts](https://img.shields.io/github/stars/rva3/CVE-2026-40003.svg) ![forks](https://img.shields.io/github/forks/rva3/CVE-2026-40003.svg)

## CVE-2026-39987
 marimo is a reactive Python notebook. Prior to 0.23.0, Marimo has a Pre-Auth RCE vulnerability. The terminal WebSocket endpoint /terminal/ws lacks authentication validation, allowing an unauthenticated attacker to obtain a full PTY shell and execute arbitrary system commands. Unlike other WebSocket endpoints (e.g., /ws) that correctly call validate_auth() for authentication, the /terminal/ws endpoint only checks the running mode and platform support before accepting connections, completely skipping authentication verification. This vulnerability is fixed in 0.23.0.



- [https://github.com/0xBlackash/CVE-2026-39987](https://github.com/0xBlackash/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-39987.svg)

- [https://github.com/Nxploited/CVE-2026-39987](https://github.com/Nxploited/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-39987.svg)

- [https://github.com/keraattin/CVE-2026-39987](https://github.com/keraattin/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/keraattin/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/keraattin/CVE-2026-39987.svg)

- [https://github.com/h3raklez/CVE-2026-39987](https://github.com/h3raklez/CVE-2026-39987) :  ![starts](https://img.shields.io/github/stars/h3raklez/CVE-2026-39987.svg) ![forks](https://img.shields.io/github/forks/h3raklez/CVE-2026-39987.svg)

- [https://github.com/rootdirective-sec/CVE-2026-39987-Lab](https://github.com/rootdirective-sec/CVE-2026-39987-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-39987-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-39987-Lab.svg)

- [https://github.com/mki9/CVE-2026-39987_exploit](https://github.com/mki9/CVE-2026-39987_exploit) :  ![starts](https://img.shields.io/github/stars/mki9/CVE-2026-39987_exploit.svg) ![forks](https://img.shields.io/github/forks/mki9/CVE-2026-39987_exploit.svg)

- [https://github.com/fevar54/marimo_CVE-2026-39987_RCE_PoC](https://github.com/fevar54/marimo_CVE-2026-39987_RCE_PoC) :  ![starts](https://img.shields.io/github/stars/fevar54/marimo_CVE-2026-39987_RCE_PoC.svg) ![forks](https://img.shields.io/github/forks/fevar54/marimo_CVE-2026-39987_RCE_PoC.svg)

- [https://github.com/Dhiaelhak-Rached/CVE-2026-39987-lab-or-marimo-cve-lab](https://github.com/Dhiaelhak-Rached/CVE-2026-39987-lab-or-marimo-cve-lab) :  ![starts](https://img.shields.io/github/stars/Dhiaelhak-Rached/CVE-2026-39987-lab-or-marimo-cve-lab.svg) ![forks](https://img.shields.io/github/forks/Dhiaelhak-Rached/CVE-2026-39987-lab-or-marimo-cve-lab.svg)

## CVE-2026-39983
 basic-ftp is an FTP client for Node.js. Prior to 5.2.1, basic-ftp allows FTP command injection via CRLF sequences (\r\n) in file path parameters passed to high-level path APIs such as cd(), remove(), rename(), uploadFrom(), downloadTo(), list(), and removeDir(). The library's protectWhitespace() helper only handles leading spaces and returns other paths unchanged, while FtpContext.send() writes the resulting command string directly to the control socket with \r\n appended. This lets attacker-controlled path strings split one intended FTP command into multiple commands. This vulnerability is fixed in 5.2.1.



- [https://github.com/zebbernCVE/CVE-2026-39983](https://github.com/zebbernCVE/CVE-2026-39983) :  ![starts](https://img.shields.io/github/stars/zebbernCVE/CVE-2026-39983.svg) ![forks](https://img.shields.io/github/forks/zebbernCVE/CVE-2026-39983.svg)

## CVE-2026-39973
 Apktool is a tool for reverse engineering Android APK files. In versions 3.0.0 and 3.0.1, a path traversal vulnerability in `brut/androlib/res/decoder/ResFileDecoder.java` allows a maliciously crafted APK to write arbitrary files to the filesystem during standard decoding (`apktool d`). This is a security regression introduced in commit e10a045 (PR #4041, December 12, 2025), which removed the `BrutIO.sanitizePath()` call that previously prevented path traversal in resource file output paths. An attacker can embed `../` sequences in the `resources.arsc` Type String Pool to escape the output directory and write files to arbitrary locations, including `~/.ssh/config`, `~/.bashrc`, or Windows Startup folders, escalating to RCE. The fix in version 3.0.2 re-introduces `BrutIO.sanitizePath()` in `ResFileDecoder.java` before file write operations.



- [https://github.com/frawlaboy/CVE-2026-39973-PoC](https://github.com/frawlaboy/CVE-2026-39973-PoC) :  ![starts](https://img.shields.io/github/stars/frawlaboy/CVE-2026-39973-PoC.svg) ![forks](https://img.shields.io/github/forks/frawlaboy/CVE-2026-39973-PoC.svg)

## CVE-2026-39912
 V2Board 1.6.1 through 1.7.4 and Xboard through 0.1.9 expose authentication tokens in HTTP response bodies of the loginWithMailLink endpoint when the login_with_mail_link_enable feature is active. Unauthenticated attackers can POST to the loginWithMailLink endpoint with a known email address to receive the full authentication URL in the response, then exchange the token at the token2Login endpoint to obtain a valid bearer token with complete account access including admin privileges.



- [https://github.com/Chocapikk/CVE-2026-39912](https://github.com/Chocapikk/CVE-2026-39912) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2026-39912.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2026-39912.svg)

## CVE-2026-39866
 Lawnchair is a free, open-source home app for Android. Prior to commit fcba413f55dd47f8a3921445252849126c6266b2, command injection in release_update.yml workflow dispatch input allows arbitrary code execution. Commit fcba413f55dd47f8a3921445252849126c6266b2 patches the issue.



- [https://github.com/abhayclasher/CVE-2026-39866](https://github.com/abhayclasher/CVE-2026-39866) :  ![starts](https://img.shields.io/github/stars/abhayclasher/CVE-2026-39866.svg) ![forks](https://img.shields.io/github/forks/abhayclasher/CVE-2026-39866.svg)

## CVE-2026-39842
 OpenRemote is an open-source IoT platform. Versions 1.21.0 and below contain two interrelated expression injection vulnerabilities in the rules engine that allow arbitrary code execution on the server. The JavaScript rules engine executes user-supplied scripts via Nashorn's ScriptEngine.eval() without sandboxing, class filtering, or access restrictions, and the authorization check in RulesResourceImpl only restricts Groovy rules to superusers while leaving JavaScript rules unrestricted for any user with the write:rules role. Additionally, the Groovy rules engine has a GroovyDenyAllFilter security filter that is defined but never registered, as the registration code is commented out, rendering the SandboxTransformer ineffective for superuser-created Groovy rules. A non-superuser attacker with the write:rules role can create JavaScript rulesets that execute with full JVM access, enabling remote code execution as root, arbitrary file read, environment variable theft including database credentials, and complete multi-tenant isolation bypass to access data across all realms. This issue has been fixed in version 1.22.0.



- [https://github.com/keraattin/CVE-2026-39842](https://github.com/keraattin/CVE-2026-39842) :  ![starts](https://img.shields.io/github/stars/keraattin/CVE-2026-39842.svg) ![forks](https://img.shields.io/github/forks/keraattin/CVE-2026-39842.svg)

## CVE-2026-39816
 The optional extension component TinkerpopClientService is missing the Restricted annotation with the Execute Code Required Permission in Apache NiFi 2.0.0-M1 through 2.8.0. The TinkerpopClientService supports configuration of ByteCode Submission for the Script Submission Type, enabling Groovy Script execution in the service prior to submitting the query. The missing Restricted annotation allows users without the Execute Code Permission to configure the Service in installations that use fine-grained authorization and have the optional TinkerpopClientService installed. Apache NiFi installations that do not have the nifi-other-graph-services-nar installed are not subject to this vulnerability. Upgrading to Apache NiFi 2.9.0 is the recommended mitigation.



- [https://github.com/ZeroPathAI/nifi-CVE-2026-39816-poc](https://github.com/ZeroPathAI/nifi-CVE-2026-39816-poc) :  ![starts](https://img.shields.io/github/stars/ZeroPathAI/nifi-CVE-2026-39816-poc.svg) ![forks](https://img.shields.io/github/forks/ZeroPathAI/nifi-CVE-2026-39816-poc.svg)

## CVE-2026-39813
 A path traversal: '../filedir' vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.5, FortiSandbox 4.4.0 through 4.4.8 may allow attacker to escalation of privilege via insert attack vector here



- [https://github.com/0xBlackash/CVE-2026-39813](https://github.com/0xBlackash/CVE-2026-39813) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-39813.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-39813.svg)

## CVE-2026-39808
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 4.4.0 through 4.4.8 may allow attacker to execute unauthorized code or commands via insert attack vector here



- [https://github.com/ynsmroztas/FortiSandbox-RCE-Exploit-CVE-2026-39808](https://github.com/ynsmroztas/FortiSandbox-RCE-Exploit-CVE-2026-39808) :  ![starts](https://img.shields.io/github/stars/ynsmroztas/FortiSandbox-RCE-Exploit-CVE-2026-39808.svg) ![forks](https://img.shields.io/github/forks/ynsmroztas/FortiSandbox-RCE-Exploit-CVE-2026-39808.svg)

- [https://github.com/samu-delucas/CVE-2026-39808](https://github.com/samu-delucas/CVE-2026-39808) :  ![starts](https://img.shields.io/github/stars/samu-delucas/CVE-2026-39808.svg) ![forks](https://img.shields.io/github/forks/samu-delucas/CVE-2026-39808.svg)

- [https://github.com/0xBlackash/CVE-2026-39808](https://github.com/0xBlackash/CVE-2026-39808) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-39808.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-39808.svg)

- [https://github.com/Lechansky/CVE-2026-39808](https://github.com/Lechansky/CVE-2026-39808) :  ![starts](https://img.shields.io/github/stars/Lechansky/CVE-2026-39808.svg) ![forks](https://img.shields.io/github/forks/Lechansky/CVE-2026-39808.svg)

## CVE-2026-39440
 Improper Control of Generation of Code ('Code Injection') vulnerability in Funnelforms LLC FunnelFormsPro allows Remote Code Inclusion.This issue affects FunnelFormsPro: from n/a through 3.8.1.



- [https://github.com/3ele-projects/cve-2026-39440-funnelforms-fix](https://github.com/3ele-projects/cve-2026-39440-funnelforms-fix) :  ![starts](https://img.shields.io/github/stars/3ele-projects/cve-2026-39440-funnelforms-fix.svg) ![forks](https://img.shields.io/github/forks/3ele-projects/cve-2026-39440-funnelforms-fix.svg)

## CVE-2026-39387
 BoidCMS is an open-source, PHP-based flat-file CMS for building simple websites and blogs, using JSON as its database. Versions prior to 2.1.3 are vulnerable to a critical Local File Inclusion (LFI) attack via the tpl parameter, which can lead to Remote Code Execution (RCE).The application fails to sanitize the tpl (template) parameter during page creation and updates. This parameter is passed directly to a require_once() statement without path validation. An authenticated administrator can exploit this by injecting path traversal sequences (../) into the tpl value to escape the intended theme directory and include arbitrary files — specifically, files from the server's media/ directory. When combined with the file upload functionality, this becomes a full RCE chain: an attacker can first upload a file with embedded PHP code (e.g., disguised as image data), then use the path traversal vulnerability to include that file via require_once(), executing the embedded code with web server privileges. This issue has been fixed in version 2.1.3.



- [https://github.com/xp1tr/CVE-2026-39387](https://github.com/xp1tr/CVE-2026-39387) :  ![starts](https://img.shields.io/github/stars/xp1tr/CVE-2026-39387.svg) ![forks](https://img.shields.io/github/forks/xp1tr/CVE-2026-39387.svg)

## CVE-2026-39376
 FastFeedParser is a high performance RSS, Atom and RDF parser. Prior to 0.5.10, when parse() fetches a URL that returns an HTML page containing a meta http-equiv="refresh" tag, it recursively calls itself with the redirect URL — with no depth limit, no visited-URL deduplication, and no redirect count cap. An attacker-controlled server that returns an infinite chain of HTML meta-refresh responses causes unbounded recursion, exhausting the Python call stack and crashing the process. This vulnerability can also be chained with the companion SSRF issue to reach internal network targets after bypassing the initial URL check. This vulnerability is fixed in 0.5.10.



- [https://github.com/redyank/CVE-2026-39376](https://github.com/redyank/CVE-2026-39376) :  ![starts](https://img.shields.io/github/stars/redyank/CVE-2026-39376.svg) ![forks](https://img.shields.io/github/forks/redyank/CVE-2026-39376.svg)

## CVE-2026-39371
 RedwoodSDK is a server-first React framework. From 1.0.0-beta.50 to 1.0.5, erver functions exported from "use server" files could be invoked via GET requests, bypassing their intended HTTP method. In cookie-authenticated applications, this allowed cross-site GET navigations to trigger state-changing functions, because browsers send SameSite=Lax cookies on top-level GET requests. This affected all server functions -- both serverAction() handlers and bare exported functions in "use server" files. This vulnerability is fixed in 1.0.6.



- [https://github.com/zebbernCVE/CVE-2026-39371](https://github.com/zebbernCVE/CVE-2026-39371) :  ![starts](https://img.shields.io/github/stars/zebbernCVE/CVE-2026-39371.svg) ![forks](https://img.shields.io/github/forks/zebbernCVE/CVE-2026-39371.svg)

## CVE-2026-39363
 Vite is a frontend tooling framework for JavaScript. From 6.0.0 to before 6.4.2, 7.3.2, and 8.0.5, if it is possible to connect to the Vite dev server’s WebSocket without an Origin header, an attacker can invoke fetchModule via the custom WebSocket event vite:invoke and combine file://... with ?raw (or ?inline) to retrieve the contents of arbitrary files on the server as a JavaScript string (e.g., export default "..."). The access control enforced in the HTTP request path (such as server.fs.allow) is not applied to this WebSocket-based execution path. This vulnerability is fixed in 6.4.2, 7.3.2, and 8.0.5.



- [https://github.com/Firebasky/CVE-2026-39363](https://github.com/Firebasky/CVE-2026-39363) :  ![starts](https://img.shields.io/github/stars/Firebasky/CVE-2026-39363.svg) ![forks](https://img.shields.io/github/forks/Firebasky/CVE-2026-39363.svg)

- [https://github.com/f4s1on/CVE-2026-39363](https://github.com/f4s1on/CVE-2026-39363) :  ![starts](https://img.shields.io/github/stars/f4s1on/CVE-2026-39363.svg) ![forks](https://img.shields.io/github/forks/f4s1on/CVE-2026-39363.svg)

## CVE-2026-39324
 Rack::Session is a session management implementation for Rack. From 2.0.0 to before 2.1.2, Rack::Session::Cookie incorrectly handles decryption failures when configured with secrets:. If cookie decryption fails, the implementation falls back to a default decoder instead of rejecting the cookie. This allows an unauthenticated attacker to supply a crafted session cookie that is accepted as valid session data without knowledge of any configured secret. Because this mechanism is used to load session state, an attacker can manipulate session contents and potentially gain unauthorized access. This vulnerability is fixed in 2.1.2.



- [https://github.com/sm1ee/CVE-2026-39324](https://github.com/sm1ee/CVE-2026-39324) :  ![starts](https://img.shields.io/github/stars/sm1ee/CVE-2026-39324.svg) ![forks](https://img.shields.io/github/forks/sm1ee/CVE-2026-39324.svg)

## CVE-2026-38936
 A reflected cross-site scripting (XSS) vulnerability exists in diskover-community = 2.3.5 in public/selectindices.php via the namecontains parameter



- [https://github.com/VadlaReddySai/diskoverdata-cve-writeups](https://github.com/VadlaReddySai/diskoverdata-cve-writeups) :  ![starts](https://img.shields.io/github/stars/VadlaReddySai/diskoverdata-cve-writeups.svg) ![forks](https://img.shields.io/github/forks/VadlaReddySai/diskoverdata-cve-writeups.svg)

## CVE-2026-38935
 A reflected cross-site scripting (XSS) vulnerability exists in diskover-community = 2.3.5 in public/view.php via the doctype parameter



- [https://github.com/VadlaReddySai/diskoverdata-cve-writeups](https://github.com/VadlaReddySai/diskoverdata-cve-writeups) :  ![starts](https://img.shields.io/github/stars/VadlaReddySai/diskoverdata-cve-writeups.svg) ![forks](https://img.shields.io/github/forks/VadlaReddySai/diskoverdata-cve-writeups.svg)

## CVE-2026-38934
 Cross Site Request Forgery vulnerability in diskoverdata diskover-community v.2.3.5. and before allows a remote attacker to escalate privileges and obtain sensitive information via the public/settings_process.php



- [https://github.com/VadlaReddySai/diskoverdata-cve-writeups](https://github.com/VadlaReddySai/diskoverdata-cve-writeups) :  ![starts](https://img.shields.io/github/stars/VadlaReddySai/diskoverdata-cve-writeups.svg) ![forks](https://img.shields.io/github/forks/VadlaReddySai/diskoverdata-cve-writeups.svg)

## CVE-2026-38361
 An issue in fohrloop dash-uploader v.0.1.0 through v.0.7.0a2 allows a remote attacker to execute arbitrary code via the dash_uploader/httprequesthandler.py, dash_uploader/upload.py in the Upload function and max_file_size parameter, dash_uploader/configure_upload.py components



- [https://github.com/a1ohadance/CVE-2026-38361](https://github.com/a1ohadance/CVE-2026-38361) :  ![starts](https://img.shields.io/github/stars/a1ohadance/CVE-2026-38361.svg) ![forks](https://img.shields.io/github/forks/a1ohadance/CVE-2026-38361.svg)

## CVE-2026-38360
 Directory Traversal vulnerability in fohrloop dash-uploader v.0.1.0 through v.0.7.0a2 allows a remote attacker to execute arbitrary code via the dash_uploader/httprequesthandler.py, aseHttpRequestHandler.get_temp_root(), BaseHttpRequestHandler._post() components



- [https://github.com/a1ohadance/CVE-2026-38360](https://github.com/a1ohadance/CVE-2026-38360) :  ![starts](https://img.shields.io/github/stars/a1ohadance/CVE-2026-38360.svg) ![forks](https://img.shields.io/github/forks/a1ohadance/CVE-2026-38360.svg)

## CVE-2026-37750
 A reflected Cross-Site Scripting (XSS) vulnerability in School Management System by mahmoudai1 allows unauthenticated remote attackers to execute arbitrary JavaScript in victim's browsers via the unsanitized type parameter in register.php.



- [https://github.com/menevarad007/CVE-2026-37750](https://github.com/menevarad007/CVE-2026-37750) :  ![starts](https://img.shields.io/github/stars/menevarad007/CVE-2026-37750.svg) ![forks](https://img.shields.io/github/forks/menevarad007/CVE-2026-37750.svg)

## CVE-2026-37749
 A SQL injection vulnerability in CodeAstro Simple Attendance Management System v1.0 allows remote unauthenticated attackers to bypass authentication via the username parameter in index.php.



- [https://github.com/menevarad007/CVE-2026-37749](https://github.com/menevarad007/CVE-2026-37749) :  ![starts](https://img.shields.io/github/stars/menevarad007/CVE-2026-37749.svg) ![forks](https://img.shields.io/github/forks/menevarad007/CVE-2026-37749.svg)

## CVE-2026-37748
 Visitor Management System 1.0 by sanjay1313 is vulnerable to Unrestricted File Upload in vms/php/admin_user_insert.php and vms/php/update_1.php. The move_uploaded_file() function is called without any MIME type, extension, or content validation, allowing an authenticated admin to upload a PHP webshell and achieve Remote Code Execution on the server.



- [https://github.com/menevarad007/CVE-2026-37748](https://github.com/menevarad007/CVE-2026-37748) :  ![starts](https://img.shields.io/github/stars/menevarad007/CVE-2026-37748.svg) ![forks](https://img.shields.io/github/forks/menevarad007/CVE-2026-37748.svg)

## CVE-2026-36960
 A Cross-Site Request Forgery (CSRF) vulnerability exists in the web management interface of the U-SPEED N300 Rounter V1.0.0. The device does not implement CSRF protection mechanisms such as anti-CSRF tokens or strict Origin/Referer validation for administrative API endpoints. An attacker can craft a malicious webpage that sends forged HTTP requests to configuration endpoints. If an authenticated administrator visits the malicious webpage, the victim's browser automatically includes the valid session cookie in the request, allowing the router to process the request as a legitimate administrative action.



- [https://github.com/kirubel-cve/CVE-2026-36960](https://github.com/kirubel-cve/CVE-2026-36960) :  ![starts](https://img.shields.io/github/stars/kirubel-cve/CVE-2026-36960.svg) ![forks](https://img.shields.io/github/forks/kirubel-cve/CVE-2026-36960.svg)

## CVE-2026-36959
 U-SPEED N300 router V1.0.0 does not implement rate limiting or account lockout protections on the /api/login endpoint. This allows an attacker on the local network to perform unlimited authentication attempts, enabling brute-force attacks against the administrator account and potential unauthorized access to the router management interface.



- [https://github.com/kirubel-cve/CVE-2026-36959](https://github.com/kirubel-cve/CVE-2026-36959) :  ![starts](https://img.shields.io/github/stars/kirubel-cve/CVE-2026-36959.svg) ![forks](https://img.shields.io/github/forks/kirubel-cve/CVE-2026-36959.svg)

## CVE-2026-36958
 A denial-of-service vulnerability exists in the U-SPEED N300 V1.0.0 wireless router. By sending a large number of concurrent HTTP requests to random or non-existent endpoints on the web management interface, an attacker can exhaust system resources in the embedded Boa HTTP server. This causes the router web interface to become unresponsive and may require manual reboot to restore normal operation.



- [https://github.com/kirubel-cve/CVE-2026-36958](https://github.com/kirubel-cve/CVE-2026-36958) :  ![starts](https://img.shields.io/github/stars/kirubel-cve/CVE-2026-36958.svg) ![forks](https://img.shields.io/github/forks/kirubel-cve/CVE-2026-36958.svg)

## CVE-2026-36957
 Dbit N300 T1 Pro Easy Setup Wireless Wi-Fi Router V1.0.0 is vulnerable to Denial of Service via the boa web server URI handler. By initiating a high-volume flood of HTTP GET requests to non-existent URIs, an attacker can exhaust critical system resources, including file descriptors and memory buffers. This results in a kernel deadlock or system hang that disables the web management portal and all routing capabilities.



- [https://github.com/kirubel-cve/CVE-2026-36957](https://github.com/kirubel-cve/CVE-2026-36957) :  ![starts](https://img.shields.io/github/stars/kirubel-cve/CVE-2026-36957.svg) ![forks](https://img.shields.io/github/forks/kirubel-cve/CVE-2026-36957.svg)

## CVE-2026-36956
 A Cross-Site Request Forgery (CSRF) vulnerability exists in the web management interface of the Dbit N300 T1 Pro wireless router V1.0.0. The router fails to implement proper CSRF protection mechanisms such as anti-CSRF tokens or strict Origin/Referer validation for administrative API endpoints. An attacker can craft a malicious webpage that sends forged HTTP requests to configuration endpoints such as /api/setWlan. If an authenticated administrator visits the malicious webpage, the victim's browser automatically includes the valid session cookie in the request, allowing the router to process the request as a legitimate administrative action.



- [https://github.com/kirubel-cve/CVE-2026-36956](https://github.com/kirubel-cve/CVE-2026-36956) :  ![starts](https://img.shields.io/github/stars/kirubel-cve/CVE-2026-36956.svg) ![forks](https://img.shields.io/github/forks/kirubel-cve/CVE-2026-36956.svg)

## CVE-2026-36358
 Cross Site Scripting vulnerability in Juzaweb CMS v.5.0.0 allows a remote attacker via execute arbitrary code via a crafted script to the Add Banner Ads function



- [https://github.com/yuhuamiao/CVE-2026-36358](https://github.com/yuhuamiao/CVE-2026-36358) :  ![starts](https://img.shields.io/github/stars/yuhuamiao/CVE-2026-36358.svg) ![forks](https://img.shields.io/github/forks/yuhuamiao/CVE-2026-36358.svg)

## CVE-2026-36356
 The GoAhead web server on MeiG Smart FORGE_SLT711 devices (firmware MDM9607.LE.1.0-00110-STD.PROD-1) allows unauthenticated OS command injection via the /action/SetRemoteAccessCfg endpoint.



- [https://github.com/totekuh/CVE-2026-36356](https://github.com/totekuh/CVE-2026-36356) :  ![starts](https://img.shields.io/github/stars/totekuh/CVE-2026-36356.svg) ![forks](https://img.shields.io/github/forks/totekuh/CVE-2026-36356.svg)

## CVE-2026-36355
 The rtl8192cd Wi-Fi kernel driver in the Realtek rtl819x Jungle SDK (all known versions through v3.4.14B) does not perform any access control checks on the write_mem (ioctl 0x89F5) and read_mem (ioctl 0x89F6) debug handlers, which are compiled into production builds via the unconditionally defined _IOCTL_DEBUG_CMD_ macro in 8192cd_cfg.h



- [https://github.com/totekuh/CVE-2026-36355](https://github.com/totekuh/CVE-2026-36355) :  ![starts](https://img.shields.io/github/stars/totekuh/CVE-2026-36355.svg) ![forks](https://img.shields.io/github/forks/totekuh/CVE-2026-36355.svg)

## CVE-2026-36341
 Cross-Site Scripting (XSS) vulnerability exists in Webkul Krayin CRM v2.1.5. The application fails to sanitize user-supplied input in the comment field during Activity creation on the /admin/activities/create endpoint



- [https://github.com/cybercrewinc/CVE-2026-36341](https://github.com/cybercrewinc/CVE-2026-36341) :  ![starts](https://img.shields.io/github/stars/cybercrewinc/CVE-2026-36341.svg) ![forks](https://img.shields.io/github/forks/cybercrewinc/CVE-2026-36341.svg)

## CVE-2026-36340
 An issue in Krayin CRM v.2.1.5 and fixed in v.2.1.6 allows a remote attacker to execute arbitrary code via the compose email function



- [https://github.com/cybercrewinc/CVE-2026-36340](https://github.com/cybercrewinc/CVE-2026-36340) :  ![starts](https://img.shields.io/github/stars/cybercrewinc/CVE-2026-36340.svg) ![forks](https://img.shields.io/github/forks/cybercrewinc/CVE-2026-36340.svg)

## CVE-2026-35616
 A improper access control vulnerability in Fortinet FortiClientEMS 7.4.5 through 7.4.6 may allow an unauthenticated attacker to execute unauthorized code or commands via crafted requests.



- [https://github.com/Alaatk/CVE-2026-35616](https://github.com/Alaatk/CVE-2026-35616) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2026-35616.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2026-35616.svg)

- [https://github.com/wa6n3r/CVE-2026-35616](https://github.com/wa6n3r/CVE-2026-35616) :  ![starts](https://img.shields.io/github/stars/wa6n3r/CVE-2026-35616.svg) ![forks](https://img.shields.io/github/forks/wa6n3r/CVE-2026-35616.svg)

- [https://github.com/0xBlackash/CVE-2026-35616](https://github.com/0xBlackash/CVE-2026-35616) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-35616.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-35616.svg)

- [https://github.com/keraattin/CVE-2026-35616](https://github.com/keraattin/CVE-2026-35616) :  ![starts](https://img.shields.io/github/stars/keraattin/CVE-2026-35616.svg) ![forks](https://img.shields.io/github/forks/keraattin/CVE-2026-35616.svg)

- [https://github.com/BishopFox/CVE-2026-35616-check](https://github.com/BishopFox/CVE-2026-35616-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2026-35616-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2026-35616-check.svg)

- [https://github.com/fevar54/CVE-2026-35616-detector.py](https://github.com/fevar54/CVE-2026-35616-detector.py) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-35616-detector.py.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-35616-detector.py.svg)

- [https://github.com/fevar54/forticlient_ems_cve_2026_35616_poc.py](https://github.com/fevar54/forticlient_ems_cve_2026_35616_poc.py) :  ![starts](https://img.shields.io/github/stars/fevar54/forticlient_ems_cve_2026_35616_poc.py.svg) ![forks](https://img.shields.io/github/forks/fevar54/forticlient_ems_cve_2026_35616_poc.py.svg)

## CVE-2026-35585
 File Browser is a file managing interface for uploading, deleting, previewing, renaming, and editing files within a specified directory. From 2.0.0 through 2.63.1, the hook system in File Browser — which executes administrator-defined shell commands on file events such as upload, rename, and delete — is vulnerable to OS command injection. Variable substitution for values like $FILE and $USERNAME is performed via os.Expand without sanitization. An attacker with file write permission can craft a malicious filename containing shell metacharacters, causing the server to execute arbitrary OS commands when the hook fires. This results in Remote Code Execution (RCE). This feature has been disabled by default for all installations from v2.33.8 onwards, including for existent installations.



- [https://github.com/Saku0512/CVE-2026-35585-poc](https://github.com/Saku0512/CVE-2026-35585-poc) :  ![starts](https://img.shields.io/github/stars/Saku0512/CVE-2026-35585-poc.svg) ![forks](https://img.shields.io/github/forks/Saku0512/CVE-2026-35585-poc.svg)

## CVE-2026-35584
 FreeScout is a free help desk and shared inbox built with PHP's Laravel framework. Prior to 1.8.212, the endpoint GET /thread/read/{conversation_id}/{thread_id} does not require authentication and does not validate whether the given thread_id belongs to the given conversation_id. This allows any unauthenticated attacker to mark any thread as read by passing arbitrary IDs, enumerate valid thread IDs via HTTP response codes (200 vs 404), and manipulate opened_at timestamps across conversations (IDOR). This vulnerability is fixed in 1.8.212.



- [https://github.com/LeonardoNovais7/CVE-2026-35584](https://github.com/LeonardoNovais7/CVE-2026-35584) :  ![starts](https://img.shields.io/github/stars/LeonardoNovais7/CVE-2026-35584.svg) ![forks](https://img.shields.io/github/forks/LeonardoNovais7/CVE-2026-35584.svg)

## CVE-2026-35570
 OpenClaude is an open-source coding-agent command line interface for cloud and local model providers. Versions prior to 0.5.1 have a logic flaw in `bashToolHasPermission()` inside `src/tools/BashTool/bashPermissions.ts`. When the sandbox auto-allow feature is active and no explicit deny rule is configured, the function returns an `allow` result immediately — before the path constraint filter (`checkPathConstraints`) is ever evaluated. This allows commands containing path traversal sequences (e.g., `../../../../../etc/passwd`) to bypass directory restrictions entirely. Version 0.5.1 contains a patch for the issue.



- [https://github.com/Rickidevs/CVE-2026-35570](https://github.com/Rickidevs/CVE-2026-35570) :  ![starts](https://img.shields.io/github/stars/Rickidevs/CVE-2026-35570.svg) ![forks](https://img.shields.io/github/forks/Rickidevs/CVE-2026-35570.svg)

## CVE-2026-35517
 FTLDNS (pihole-FTL) provides an interactive API and also generates statistics for Pi-hole's Web interface. From 6.0 to before 6.6, the Pi-hole FTL engine contains a Remote Code Execution (RCE) vulnerability in the upstream DNS servers configuration parameter (dns.upstreams). This vulnerability allows an authenticated attacker to inject arbitrary dnsmasq configuration directives through newline characters, ultimately achieving command execution on the underlying system. This vulnerability is fixed in 6.6.



- [https://github.com/keraattin/CVE-2026-35517](https://github.com/keraattin/CVE-2026-35517) :  ![starts](https://img.shields.io/github/stars/keraattin/CVE-2026-35517.svg) ![forks](https://img.shields.io/github/forks/keraattin/CVE-2026-35517.svg)

## CVE-2026-35492
 Kedro-Datasets is a Kendo plugin providing data connectors. Prior to 9.3.0, PartitionedDataset in kedro-datasets was vulnerable to path traversal. Partition IDs were concatenated directly with the dataset base path without validation. An attacker or malicious input containing .. components in a partition ID could cause files to be written outside the configured dataset directory, potentially overwriting arbitrary files on the filesystem. Users of PartitionedDataset with any storage backend (local filesystem, S3, GCS, etc.) are affected. This vulnerability is fixed in 9.3.0.



- [https://github.com/redyank/CVE-2026-35492](https://github.com/redyank/CVE-2026-35492) :  ![starts](https://img.shields.io/github/stars/redyank/CVE-2026-35492.svg) ![forks](https://img.shields.io/github/forks/redyank/CVE-2026-35492.svg)

## CVE-2026-35414
 OpenSSH before 10.3 mishandles the authorized_keys principals option in uncommon scenarios involving a principals list in conjunction with a Certificate Authority that makes certain use of comma characters.



- [https://github.com/killercd/CVE-2026-35414](https://github.com/killercd/CVE-2026-35414) :  ![starts](https://img.shields.io/github/stars/killercd/CVE-2026-35414.svg) ![forks](https://img.shields.io/github/forks/killercd/CVE-2026-35414.svg)

- [https://github.com/dehobbs/cve_2026_35414](https://github.com/dehobbs/cve_2026_35414) :  ![starts](https://img.shields.io/github/stars/dehobbs/cve_2026_35414.svg) ![forks](https://img.shields.io/github/forks/dehobbs/cve_2026_35414.svg)

## CVE-2026-35397
 Jupyter Server is the backend for Jupyter web applications. In versions 2.17.0 and earlier, a path traversal vulnerability in the REST API allows an authenticated user to escape the configured root_dir and access sibling directories whose names begin with the same prefix as the root_dir. For example, with a root_dir named "test", the API permits access to a sibling directory named "testtest" through a crafted request to the /api/contents endpoint using encoded path components. An attacker can read, write, and delete files in affected sibling directories. Multi-tenant deployments using predictable naming schemes are particularly at risk, as a user with a directory named "user1" could access directories for user10 through user19 and beyond. A user who can choose a single-character folder name could gain access to a significant number of sibling directories. 

Version 2.18.0 contains a fix. As a workaround, ensure folder names do not share a common prefix with any sibling directory.



- [https://github.com/HiteshGorana/susvibes-jupyter-server-cve-2026-35397](https://github.com/HiteshGorana/susvibes-jupyter-server-cve-2026-35397) :  ![starts](https://img.shields.io/github/stars/HiteshGorana/susvibes-jupyter-server-cve-2026-35397.svg) ![forks](https://img.shields.io/github/forks/HiteshGorana/susvibes-jupyter-server-cve-2026-35397.svg)

## CVE-2026-35250
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core).   The supported version that is affected is 7.2.6. Easily exploitable vulnerability allows high privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox.  Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Oracle VM VirtualBox. CVSS 3.1 Base Score 2.3 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L).



- [https://github.com/xooxo/CVE-2026-35250](https://github.com/xooxo/CVE-2026-35250) :  ![starts](https://img.shields.io/github/stars/xooxo/CVE-2026-35250.svg) ![forks](https://img.shields.io/github/forks/xooxo/CVE-2026-35250.svg)

## CVE-2026-35045
 Tandoor Recipes is an application for managing recipes, planning meals, and building shopping lists. Prior to 2.6.4, the PUT /api/recipe/batch_update/ endpoint in Tandoor Recipes allows any authenticated user within a Space to modify any recipe in that Space, including recipes marked as private by other users. This bypasses all object-level authorization checks enforced on standard single-recipe endpoints (PUT /api/recipe/{id}/), enabling forced exposure of private recipes, unauthorized self-grant of access via the shared list, and metadata tampering. This vulnerability is fixed in 2.6.4.



- [https://github.com/FilipeGaudard/CVE-2026-35045-PoC](https://github.com/FilipeGaudard/CVE-2026-35045-PoC) :  ![starts](https://img.shields.io/github/stars/FilipeGaudard/CVE-2026-35045-PoC.svg) ![forks](https://img.shields.io/github/forks/FilipeGaudard/CVE-2026-35045-PoC.svg)

## CVE-2026-35031
 Jellyfin is an open source self hosted media server. Versions prior to 10.11.7 contain a vulnerability chain in the subtitle upload endpoint (POST /Videos/{itemId}/Subtitles), where the Format field is not validated, allowing path traversal via the file extension and enabling arbitrary file write. This arbitrary file write can be chained into arbitrary file read via .strm files, database extraction, admin privilege escalation, and ultimately remote code execution as root via ld.so.preload. Exploitation requires an administrator account or a user that has been explicitly granted the "Upload Subtitles" permission. This issue has been fixed in version 10.11.7. If users are unable to upgrade immediately, they can grant non-administrator users Subtitle upload permissions to reduce attack surface.



- [https://github.com/keraattin/CVE-2026-35031](https://github.com/keraattin/CVE-2026-35031) :  ![starts](https://img.shields.io/github/stars/keraattin/CVE-2026-35031.svg) ![forks](https://img.shields.io/github/forks/keraattin/CVE-2026-35031.svg)

## CVE-2026-34975
 Plunk is an open-source email platform built on top of AWS SES. Prior to 0.8.0, a CRLF header injection vulnerability was discovered in SESService.ts, where user-supplied values for from.name, subject, custom header keys/values, and attachment filenames were interpolated directly into raw MIME messages without sanitization. An authenticated API user could inject arbitrary email headers (e.g. Bcc, Reply-To) by embedding carriage return/line feed characters in these fields, enabling silent email forwarding, reply redirection, or sender spoofing. The fix adds input validation at the schema level to reject any of these fields containing \r or \n characters, consistent with the existing validation already applied to the contentId field. This vulnerability is fixed in 0.8.0.



- [https://github.com/romain-deperne/CVE-2026-34975](https://github.com/romain-deperne/CVE-2026-34975) :  ![starts](https://img.shields.io/github/stars/romain-deperne/CVE-2026-34975.svg) ![forks](https://img.shields.io/github/forks/romain-deperne/CVE-2026-34975.svg)

## CVE-2026-34940
 KubeAI is an AI inference operator for kubernetes. Prior to 0.23.2, the ollamaStartupProbeScript() function in internal/modelcontroller/engine_ollama.go constructs a shell command string using fmt.Sprintf with unsanitized model URL components (ref, modelParam). This shell command is executed via bash -c as a Kubernetes startup probe. An attacker who can create or update Model custom resources can inject arbitrary shell commands that execute inside model server pods. This vulnerability is fixed in 0.23.2.



- [https://github.com/romain-deperne/CVE-2026-34940](https://github.com/romain-deperne/CVE-2026-34940) :  ![starts](https://img.shields.io/github/stars/romain-deperne/CVE-2026-34940.svg) ![forks](https://img.shields.io/github/forks/romain-deperne/CVE-2026-34940.svg)

## CVE-2026-34838
 Group-Office is an enterprise customer relationship management and groupware tool. Prior to versions 6.8.156, 25.0.90, and 26.0.12, a vulnerability in the AbstractSettingsCollection model leads to insecure deserialization when these settings are loaded. By injecting a serialized FileCookieJar object into a setting string, an authenticated attacker can achieve Arbitrary File Write, leading directly to Remote Code Execution (RCE) on the server. This issue has been patched in versions 6.8.156, 25.0.90, and 26.0.12.



- [https://github.com/bamuwe/CVE-2026-34838](https://github.com/bamuwe/CVE-2026-34838) :  ![starts](https://img.shields.io/github/stars/bamuwe/CVE-2026-34838.svg) ![forks](https://img.shields.io/github/forks/bamuwe/CVE-2026-34838.svg)

## CVE-2026-34828
 listmonk is a standalone, self-hosted, newsletter and mailing list manager. From version 4.1.0 to before version 6.1.0, a session management vulnerability allows previously issued authenticated sessions to remain valid after sensitive account security changes, specifically password reset and password change. As a result, an attacker who has already obtained a valid session cookie can retain access to the account even after the victim changes or resets their password. This weakens account recovery and session security guarantees. This issue has been patched in version 6.1.0.



- [https://github.com/0xmrma/CVE-2026-34828](https://github.com/0xmrma/CVE-2026-34828) :  ![starts](https://img.shields.io/github/stars/0xmrma/CVE-2026-34828.svg) ![forks](https://img.shields.io/github/forks/0xmrma/CVE-2026-34828.svg)

## CVE-2026-34753
 vLLM is an inference and serving engine for large language models (LLMs). From 0.16.0 to before 0.19.0, a server-side request forgery (SSRF) vulnerability in download_bytes_from_url allows any actor who can control batch input JSON to make the vLLM batch runner issue arbitrary HTTP/HTTPS requests from the server, without any URL validation or domain restrictions.
This can be used to target internal services (e.g. cloud metadata endpoints or internal HTTP APIs) reachable from the vLLM host. This vulnerability is fixed in 0.19.0.



- [https://github.com/Dhiaelhak-Rached/CVE-2026-34753](https://github.com/Dhiaelhak-Rached/CVE-2026-34753) :  ![starts](https://img.shields.io/github/stars/Dhiaelhak-Rached/CVE-2026-34753.svg) ![forks](https://img.shields.io/github/forks/Dhiaelhak-Rached/CVE-2026-34753.svg)

## CVE-2026-34724
 Zammad is a web based open source helpdesk/customer support system. Prior to 7.0.1, a server-side template injection vulnerability  which leads to RCE via AI Agent exists. Impact is limited to environments where an attacker can control or influence type_enrichment_data (typically high-privilege administrative configuration). This vulnerability is fixed in 7.0.1.



- [https://github.com/0xBlackash/CVE-2026-34724](https://github.com/0xBlackash/CVE-2026-34724) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-34724.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-34724.svg)

## CVE-2026-34621
 Acrobat Reader versions 24.001.30356, 26.001.21367 and earlier are affected by an Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.



- [https://github.com/NULL200OK/cve_2026_34621_advanced](https://github.com/NULL200OK/cve_2026_34621_advanced) :  ![starts](https://img.shields.io/github/stars/NULL200OK/cve_2026_34621_advanced.svg) ![forks](https://img.shields.io/github/forks/NULL200OK/cve_2026_34621_advanced.svg)

- [https://github.com/ercihan/CVE-2026-34621](https://github.com/ercihan/CVE-2026-34621) :  ![starts](https://img.shields.io/github/stars/ercihan/CVE-2026-34621.svg) ![forks](https://img.shields.io/github/forks/ercihan/CVE-2026-34621.svg)

- [https://github.com/ercihan/CVE-2026-34621_PDF_SAMPLE](https://github.com/ercihan/CVE-2026-34621_PDF_SAMPLE) :  ![starts](https://img.shields.io/github/stars/ercihan/CVE-2026-34621_PDF_SAMPLE.svg) ![forks](https://img.shields.io/github/forks/ercihan/CVE-2026-34621_PDF_SAMPLE.svg)

- [https://github.com/KeulenR01/Remediate-AdobeAcrobat-CVE-2026-34621](https://github.com/KeulenR01/Remediate-AdobeAcrobat-CVE-2026-34621) :  ![starts](https://img.shields.io/github/stars/KeulenR01/Remediate-AdobeAcrobat-CVE-2026-34621.svg) ![forks](https://img.shields.io/github/forks/KeulenR01/Remediate-AdobeAcrobat-CVE-2026-34621.svg)

## CVE-2026-34486
 Missing Encryption of Sensitive Data vulnerability in Apache Tomcat due to the fix for CVE-2026-29146 allowing the bypass of the EncryptInterceptor.

This issue affects Apache Tomcat: 11.0.20, 10.1.53, 9.0.116.

Users are recommended to upgrade to version 11.0.21, 10.1.54 or 9.0.117, which fix the issue.



- [https://github.com/AirSkye/CVE-2026-34486-poc](https://github.com/AirSkye/CVE-2026-34486-poc) :  ![starts](https://img.shields.io/github/stars/AirSkye/CVE-2026-34486-poc.svg) ![forks](https://img.shields.io/github/forks/AirSkye/CVE-2026-34486-poc.svg)

- [https://github.com/404-src/CVE-2026-34486](https://github.com/404-src/CVE-2026-34486) :  ![starts](https://img.shields.io/github/stars/404-src/CVE-2026-34486.svg) ![forks](https://img.shields.io/github/forks/404-src/CVE-2026-34486.svg)

- [https://github.com/punitdarji/tomcat-cve-2026-34486](https://github.com/punitdarji/tomcat-cve-2026-34486) :  ![starts](https://img.shields.io/github/stars/punitdarji/tomcat-cve-2026-34486.svg) ![forks](https://img.shields.io/github/forks/punitdarji/tomcat-cve-2026-34486.svg)

- [https://github.com/helGayhub233/CVE-2026-34486-Tribes](https://github.com/helGayhub233/CVE-2026-34486-Tribes) :  ![starts](https://img.shields.io/github/stars/helGayhub233/CVE-2026-34486-Tribes.svg) ![forks](https://img.shields.io/github/forks/helGayhub233/CVE-2026-34486-Tribes.svg)

## CVE-2026-34475
 Varnish Cache before 8.0.1 and Varnish Enterprise before 6.0.16r12, in certain unchecked req.url scenarios, mishandle URLs with a path of / for HTTP/1.1, potentially leading to cache poisoning or authentication bypass.



- [https://github.com/bitbcybr/way2poc_cve-2026-34475](https://github.com/bitbcybr/way2poc_cve-2026-34475) :  ![starts](https://img.shields.io/github/stars/bitbcybr/way2poc_cve-2026-34475.svg) ![forks](https://img.shields.io/github/forks/bitbcybr/way2poc_cve-2026-34475.svg)

## CVE-2026-34444
 Lupa integrates the runtimes of Lua or LuaJIT2 into CPython. In 2.6 and earlier, attribute_filter is not consistently applied when attributes are accessed through built-in functions like getattr and setattr. This allows an attacker to bypass the intended restrictions and eventually achieve arbitrary code execution.



- [https://github.com/redyank/CVE-2026-34444](https://github.com/redyank/CVE-2026-34444) :  ![starts](https://img.shields.io/github/stars/redyank/CVE-2026-34444.svg) ![forks](https://img.shields.io/github/forks/redyank/CVE-2026-34444.svg)

## CVE-2026-34308
 Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: JSON).  Supported versions that are affected are 8.0.0-8.0.45, 8.4.0-8.4.8 and  9.0.0-9.6.0. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 6.5 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).



- [https://github.com/JoakimBulow/CVE-2026-34308](https://github.com/JoakimBulow/CVE-2026-34308) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-34308.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-34308.svg)

## CVE-2026-34227
 Sliver is a command and control framework that uses a custom Wireguard netstack. Prior to version 1.7.4, a single click on a malicious link gives an unauthenticated attacker immediate, silent control over every active C2 session or beacon, capable of exfiltrating all collected target data (e.g. SSH keys, ntds.dit) or destroying the entire compromised infrastructure, entirely through the operator's own browser. This issue has been patched in version 1.7.4.



- [https://github.com/skoveit/CVE-2026-34227](https://github.com/skoveit/CVE-2026-34227) :  ![starts](https://img.shields.io/github/stars/skoveit/CVE-2026-34227.svg) ![forks](https://img.shields.io/github/forks/skoveit/CVE-2026-34227.svg)

## CVE-2026-34220
 MikroORM is a TypeScript ORM for Node.js based on Data Mapper, Unit of Work and Identity Map patterns. Prior to versions 6.6.10 and 7.0.6, there is a SQL injection vulnerability when specially crafted objects are interpreted as raw SQL query fragments. This issue has been patched in versions 6.6.10 and 7.0.6.



- [https://github.com/EQSTLab/CVE-2026-34220](https://github.com/EQSTLab/CVE-2026-34220) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-34220.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-34220.svg)

## CVE-2026-34200
 Nhost is an open source Firebase alternative with GraphQL. Prior to version 1.41.0, The Nhost CLI MCP server, when explicitly configured to listen on a network port, applies no inbound authentication and does not enforce strict CORS. This allows a malicious website visited on the same machine to issue cross-origin requests to the MCP server and invoke privileged tools using the developer's locally configured credentials. This vulnerability requires two explicit, non-default configuration steps to be exploitable. The default nhost mcp start configuration is not affected. This issue has been patched in version 1.41.0.



- [https://github.com/skoveit/CVE-2026-34200](https://github.com/skoveit/CVE-2026-34200) :  ![starts](https://img.shields.io/github/stars/skoveit/CVE-2026-34200.svg) ![forks](https://img.shields.io/github/forks/skoveit/CVE-2026-34200.svg)

## CVE-2026-34197
 Improper Input Validation, Improper Control of Generation of Code ('Code Injection') vulnerability in Apache ActiveMQ Broker, Apache ActiveMQ.

Apache ActiveMQ Classic exposes the Jolokia JMX-HTTP bridge at /api/jolokia/ on the web console. The default Jolokia access policy permits exec operations on all ActiveMQ MBeans (org.apache.activemq:*), including
BrokerService.addNetworkConnector(String) and BrokerService.addConnector(String).

An authenticated attacker can invoke these operations with a crafted discovery URI that triggers the VM transport's brokerConfig parameter to load a remote Spring XML application context using ResourceXmlApplicationContext.
Because Spring's ResourceXmlApplicationContext instantiates all singleton beans before the BrokerService validates the configuration, arbitrary code execution occurs on the broker's JVM through bean factory methods such as Runtime.exec().



This issue affects Apache ActiveMQ Broker: before 5.19.4, from 6.0.0 before 6.2.3; Apache ActiveMQ All: before 5.19.4, from 6.0.0 before 6.2.3; Apache ActiveMQ: before 5.19.4, from 6.0.0 before 6.2.3.



Users are recommended to upgrade to version 5.19.4 or 6.2.3, which fixes the issue



- [https://github.com/Catherines77/ActiveMQ-EXPtools](https://github.com/Catherines77/ActiveMQ-EXPtools) :  ![starts](https://img.shields.io/github/stars/Catherines77/ActiveMQ-EXPtools.svg) ![forks](https://img.shields.io/github/forks/Catherines77/ActiveMQ-EXPtools.svg)

- [https://github.com/dinosn/CVE-2026-34197](https://github.com/dinosn/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-34197.svg)

- [https://github.com/DEVSECURITYSPRO/CVE-2026-34197](https://github.com/DEVSECURITYSPRO/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/DEVSECURITYSPRO/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/DEVSECURITYSPRO/CVE-2026-34197.svg)

- [https://github.com/KONDORDEVSECURITYCORP/CVE-2026-34197](https://github.com/KONDORDEVSECURITYCORP/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/KONDORDEVSECURITYCORP/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/KONDORDEVSECURITYCORP/CVE-2026-34197.svg)

- [https://github.com/AtoposX-J/CVE-2026-34197-Apache-ActiveMQ-RCE](https://github.com/AtoposX-J/CVE-2026-34197-Apache-ActiveMQ-RCE) :  ![starts](https://img.shields.io/github/stars/AtoposX-J/CVE-2026-34197-Apache-ActiveMQ-RCE.svg) ![forks](https://img.shields.io/github/forks/AtoposX-J/CVE-2026-34197-Apache-ActiveMQ-RCE.svg)

- [https://github.com/0xBlackash/CVE-2026-34197](https://github.com/0xBlackash/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-34197.svg)

- [https://github.com/rootdirective-sec/CVE-2026-34197-Lab](https://github.com/rootdirective-sec/CVE-2026-34197-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-34197-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-34197-Lab.svg)

- [https://github.com/hg0434hongzh0/CVE-2026-34197](https://github.com/hg0434hongzh0/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/hg0434hongzh0/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/hg0434hongzh0/CVE-2026-34197.svg)

- [https://github.com/keraattin/CVE-2026-34197](https://github.com/keraattin/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/keraattin/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/keraattin/CVE-2026-34197.svg)

- [https://github.com/xshysjhq/CVE-2026-34197-payload-Apache-ActiveMQ-](https://github.com/xshysjhq/CVE-2026-34197-payload-Apache-ActiveMQ-) :  ![starts](https://img.shields.io/github/stars/xshysjhq/CVE-2026-34197-payload-Apache-ActiveMQ-.svg) ![forks](https://img.shields.io/github/forks/xshysjhq/CVE-2026-34197-payload-Apache-ActiveMQ-.svg)

## CVE-2026-34160
 Chamilo LMS is an open-source learning management system. In versions prior to 2.0.0-RC.3, the PENS (Package Exchange Notification Services) plugin endpoint at public/plugin/Pens/pens.php is accessible without authentication and accepts a user-controlled package-url parameter that the server fetches using curl without filtering private or internal IP addresses, enabling unauthenticated Server-Side Request Forgery (SSRF). An attacker can exploit this to probe internal network services, access cloud metadata endpoints (such as 169.254.169.254) to steal IAM credentials and sensitive instance metadata, or trigger state-changing operations on internal services via the receipt and alerts callback parameters. No authentication is required to exploit either SSRF vector, significantly increasing the attack surface. This issue has been fixed in version 2.0.0-RC.3.



- [https://github.com/romain-deperne/CVE-2026-34160](https://github.com/romain-deperne/CVE-2026-34160) :  ![starts](https://img.shields.io/github/stars/romain-deperne/CVE-2026-34160.svg) ![forks](https://img.shields.io/github/forks/romain-deperne/CVE-2026-34160.svg)

## CVE-2026-34159
 llama.cpp is an inference of several LLM models in C/C++. Prior to version b8492, the RPC backend's deserialize_tensor() skips all bounds validation when a tensor's buffer field is 0. An unauthenticated attacker can read and write arbitrary process memory via crafted GRAPH_COMPUTE messages. Combined with pointer leaks from ALLOC_BUFFER/BUFFER_GET_BASE, this gives full ASLR bypass and remote code execution. No authentication required, just TCP access to the RPC server port. This issue has been patched in version b8492.



- [https://github.com/casp3r0x0/CVE-2026-34159](https://github.com/casp3r0x0/CVE-2026-34159) :  ![starts](https://img.shields.io/github/stars/casp3r0x0/CVE-2026-34159.svg) ![forks](https://img.shields.io/github/forks/casp3r0x0/CVE-2026-34159.svg)

- [https://github.com/rohithronanki/CVE-2026-34159-Vulnerability-Research-Analysis-Detection](https://github.com/rohithronanki/CVE-2026-34159-Vulnerability-Research-Analysis-Detection) :  ![starts](https://img.shields.io/github/stars/rohithronanki/CVE-2026-34159-Vulnerability-Research-Analysis-Detection.svg) ![forks](https://img.shields.io/github/forks/rohithronanki/CVE-2026-34159-Vulnerability-Research-Analysis-Detection.svg)

## CVE-2026-34156
 NocoBase is an AI-powered no-code/low-code platform for building business applications and enterprise solutions. Prior to version 2.0.28, NocoBase's Workflow Script Node executes user-supplied JavaScript inside a Node.js vm sandbox with a custom require allowlist (controlled by WORKFLOW_SCRIPT_MODULES env var). However, the console object passed into the sandbox context exposes host-realm WritableWorkerStdio stream objects via console._stdout and console._stderr. An authenticated attacker can traverse the prototype chain to escape the sandbox and achieve Remote Code Execution as root. This issue has been patched in version 2.0.28.



- [https://github.com/0xBlackash/CVE-2026-34156](https://github.com/0xBlackash/CVE-2026-34156) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-34156.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-34156.svg)

## CVE-2026-34070
 LangChain is a framework for building agents and LLM-powered applications. Prior to version 1.2.22, multiple functions in langchain_core.prompts.loading read files from paths embedded in deserialized config dicts without validating against directory traversal or absolute path injection. When an application passes user-influenced prompt configurations to load_prompt() or load_prompt_from_config(), an attacker can read arbitrary files on the host filesystem, constrained only by file-extension checks (.txt for templates, .json/.yaml for examples). This issue has been patched in version 1.2.22.



- [https://github.com/Rickidevs/CVE-2026-34070](https://github.com/Rickidevs/CVE-2026-34070) :  ![starts](https://img.shields.io/github/stars/Rickidevs/CVE-2026-34070.svg) ![forks](https://img.shields.io/github/forks/Rickidevs/CVE-2026-34070.svg)

## CVE-2026-34036
 Dolibarr is an enterprise resource planning (ERP) and customer relationship management (CRM) software package. In versions 22.0.4 and prior, there is a Local File Inclusion (LFI) vulnerability in the core AJAX endpoint /core/ajax/selectobject.php. By manipulating the objectdesc parameter and exploiting a fail-open logic flaw in the core access control function restrictedArea(), an authenticated user with no specific privileges can read the contents of arbitrary non-PHP files on the server (such as .env, .htaccess, configuration backups, or logs…). At time of publication, there are no publicly available patches.



- [https://github.com/cnf409/CVE-2026-34036](https://github.com/cnf409/CVE-2026-34036) :  ![starts](https://img.shields.io/github/stars/cnf409/CVE-2026-34036.svg) ![forks](https://img.shields.io/github/forks/cnf409/CVE-2026-34036.svg)

## CVE-2026-34005
 In Sofia on Xiongmai DVR/NVR (AHB7008T-MH-V2 and NBD7024H-P) 4.03.R11 devices, root OS command injection can occur via shell metacharacters in the HostName value via an authenticated DVRIP protocol (TCP port 34567) request to the NetWork.NetCommon configuration handler, because system() is used.



- [https://github.com/uky007/CVE-2026-34005](https://github.com/uky007/CVE-2026-34005) :  ![starts](https://img.shields.io/github/stars/uky007/CVE-2026-34005.svg) ![forks](https://img.shields.io/github/forks/uky007/CVE-2026-34005.svg)

## CVE-2026-33980
 Azure Data Explorer MCP Server is a Model Context Protocol (MCP) server that enables AI assistants to execute KQL queries and explore Azure Data Explorer (ADX/Kusto) databases through standardized interfaces. Versions up to and including 0.1.1 contain KQL (Kusto Query Language) injection vulnerabilities in three MCP tool handlers: `get_table_schema`, `sample_table_data`, and `get_table_details`. The `table_name` parameter is interpolated directly into KQL queries via f-strings without any validation or sanitization, allowing an attacker (or a prompt-injected AI agent) to execute arbitrary KQL queries against the Azure Data Explorer cluster. Commit 0abe0ee55279e111281076393e5e966335fffd30 patches the issue.



- [https://github.com/romain-deperne/CVE-2026-33980](https://github.com/romain-deperne/CVE-2026-33980) :  ![starts](https://img.shields.io/github/stars/romain-deperne/CVE-2026-33980.svg) ![forks](https://img.shields.io/github/forks/romain-deperne/CVE-2026-33980.svg)

## CVE-2026-33937
 Handlebars provides the power necessary to let users build semantic templates. In versions 4.0.0 through 4.7.8, `Handlebars.compile()` accepts a pre-parsed AST object in addition to a template string. The `value` field of a `NumberLiteral` AST node is emitted directly into the generated JavaScript without quoting or sanitization. An attacker who can supply a crafted AST to `compile()` can therefore inject and execute arbitrary JavaScript, leading to Remote Code Execution on the server. Version 4.7.9 fixes the issue. Some workarounds are available. Validate input type before calling `Handlebars.compile()`; ensure the argument is always a  `string`, never a plain object or JSON-deserialized value. Use the Handlebars runtime-only build (`handlebars/runtime`) on the server if templates are pre-compiled at build time; `compile()` will be unavailable.



- [https://github.com/EQSTLab/CVE-2026-33937](https://github.com/EQSTLab/CVE-2026-33937) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-33937.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-33937.svg)

- [https://github.com/dinhvaren/cve-2026-33937](https://github.com/dinhvaren/cve-2026-33937) :  ![starts](https://img.shields.io/github/stars/dinhvaren/cve-2026-33937.svg) ![forks](https://img.shields.io/github/forks/dinhvaren/cve-2026-33937.svg)

## CVE-2026-33936
 The `ecdsa` PyPI package is a pure Python implementation of ECC (Elliptic Curve Cryptography) with support for ECDSA (Elliptic Curve Digital Signature Algorithm), EdDSA (Edwards-curve Digital Signature Algorithm) and ECDH (Elliptic Curve Diffie-Hellman). Prior to version 0.19.2, an issue in the low-level DER parsing functions can cause unexpected exceptions to be raised from the public API functions. `ecdsa.der.remove_octet_string()` accepts truncated DER where the encoded length exceeds the available buffer. For example, an OCTET STRING that declares a length of 4096 bytes but provides only 3 bytes is parsed successfully instead of being rejected. Because of that, a crafted DER input can cause `SigningKey.from_der()` to raise an internal exception (`IndexError: index out of bounds on dimension 1`) rather than cleanly rejecting malformed DER (e.g., raising `UnexpectedDER` or `ValueError`). Applications that parse untrusted DER private keys may crash if they do not handle unexpected exceptions, resulting in a denial of service. Version 0.19.2 patches the issue.



- [https://github.com/0xmrma/CVE-2026-33936](https://github.com/0xmrma/CVE-2026-33936) :  ![starts](https://img.shields.io/github/stars/0xmrma/CVE-2026-33936.svg) ![forks](https://img.shields.io/github/forks/0xmrma/CVE-2026-33936.svg)

## CVE-2026-33917
 OpenEMR is a free and open source electronic health records and medical practice management application. Versions prior to 8.0.0.3 contais a SQL injection vulnerability in the ajax_save CAMOS form that can be exploited by authenticated attackers. The vulnerability exists due to insufficient input validation in the ajax_save page in the CAMOS form. Version 8.0.0.3 patches the issue.



- [https://github.com/ChrisSub08/CVE-2026-33917_SqlInjectionVulnerabilityOpenEMR8.0.0](https://github.com/ChrisSub08/CVE-2026-33917_SqlInjectionVulnerabilityOpenEMR8.0.0) :  ![starts](https://img.shields.io/github/stars/ChrisSub08/CVE-2026-33917_SqlInjectionVulnerabilityOpenEMR8.0.0.svg) ![forks](https://img.shields.io/github/forks/ChrisSub08/CVE-2026-33917_SqlInjectionVulnerabilityOpenEMR8.0.0.svg)

## CVE-2026-33910
 OpenEMR is a free and open source electronic health records and medical practice management application. Versions up to and including 8.0.0.2 contain a SQL injection vulnerability in the patient selection feature that can be exploited by authenticated attackers. The vulnerability exists due to insufficient input validation in the patient selection feature. Version 8.0.0.3 contains a patch.



- [https://github.com/ChrisSub08/CVE-2026-33910_SqlInjectionVulnerabilityOpenEMR8.0.0.2](https://github.com/ChrisSub08/CVE-2026-33910_SqlInjectionVulnerabilityOpenEMR8.0.0.2) :  ![starts](https://img.shields.io/github/stars/ChrisSub08/CVE-2026-33910_SqlInjectionVulnerabilityOpenEMR8.0.0.2.svg) ![forks](https://img.shields.io/github/forks/ChrisSub08/CVE-2026-33910_SqlInjectionVulnerabilityOpenEMR8.0.0.2.svg)

## CVE-2026-33868
 Mastodon is a free, open-source social network server based on ActivityPub. Prior to versions 4.5.8, 4.4.15, and 4.3.21, an unauthenticated Open Redirect vulnerability (CWE-601) exists in the `/web/*` route due to improper handling of URL-encoded path segments. An attacker can craft a specially encoded URL that causes the application to redirect users to an arbitrary external domain, enabling phishing attacks and potential OAuth credential theft. The issue occurs because URL-encoded slashes (`%2F`) bypass Rails path normalization and are interpreted as host-relative redirects. Versions 4.5.8, 4.4.15, and 4.3.21 patch the issue.



- [https://github.com/O99099O/By-Poloss..-..CVE-2026-33868](https://github.com/O99099O/By-Poloss..-..CVE-2026-33868) :  ![starts](https://img.shields.io/github/stars/O99099O/By-Poloss..-..CVE-2026-33868.svg) ![forks](https://img.shields.io/github/forks/O99099O/By-Poloss..-..CVE-2026-33868.svg)

## CVE-2026-33827
 Concurrent execution using shared resource with improper synchronization ('race condition') in Windows TCP/IP allows an unauthorized attacker to execute code over a network.



- [https://github.com/kaleth4/CVE-2026-33827](https://github.com/kaleth4/CVE-2026-33827) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-33827.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-33827.svg)

## CVE-2026-33826
 Improper input validation in Windows Active Directory allows an authorized attacker to execute code over an adjacent network.



- [https://github.com/kaleth4/CVE-2026-33826](https://github.com/kaleth4/CVE-2026-33826) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-33826.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-33826.svg)

## CVE-2026-33825
 Insufficient granularity of access control in Microsoft Defender allows an authorized attacker to elevate privileges locally.



- [https://github.com/Letlaka/redsun-bluehammer-undefend-detection-pack](https://github.com/Letlaka/redsun-bluehammer-undefend-detection-pack) :  ![starts](https://img.shields.io/github/stars/Letlaka/redsun-bluehammer-undefend-detection-pack.svg) ![forks](https://img.shields.io/github/forks/Letlaka/redsun-bluehammer-undefend-detection-pack.svg)

- [https://github.com/Joe1sn/CVE-2026-33825](https://github.com/Joe1sn/CVE-2026-33825) :  ![starts](https://img.shields.io/github/stars/Joe1sn/CVE-2026-33825.svg) ![forks](https://img.shields.io/github/forks/Joe1sn/CVE-2026-33825.svg)

- [https://github.com/kaleth4/CVE-2026-33825](https://github.com/kaleth4/CVE-2026-33825) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-33825.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-33825.svg)

- [https://github.com/Bilal3755/Detecting_blue_hammer_vuln](https://github.com/Bilal3755/Detecting_blue_hammer_vuln) :  ![starts](https://img.shields.io/github/stars/Bilal3755/Detecting_blue_hammer_vuln.svg) ![forks](https://img.shields.io/github/forks/Bilal3755/Detecting_blue_hammer_vuln.svg)

## CVE-2026-33824
 Double free in Windows IKE Extension allows an unauthorized attacker to execute code over a network.



- [https://github.com/kaleth4/CVE-2026-33824](https://github.com/kaleth4/CVE-2026-33824) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-33824.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-33824.svg)

## CVE-2026-33752
 curl_cffi is the a Python binding for curl. Prior to 0.15.0, curl_cffi does not restrict requests to internal IP ranges, and follows redirects automatically via the underlying libcurl. Because of this, an attacker-controlled URL can redirect requests to internal services such as cloud metadata endpoints. In addition, curl_cffi’s TLS impersonation feature can make these requests appear as legitimate browser traffic, which may bypass certain network controls. This vulnerability is fixed in 0.15.0.



- [https://github.com/redyank/CVE-2026-33752](https://github.com/redyank/CVE-2026-33752) :  ![starts](https://img.shields.io/github/stars/redyank/CVE-2026-33752.svg) ![forks](https://img.shields.io/github/forks/redyank/CVE-2026-33752.svg)

## CVE-2026-33725
 Metabase is an open source business intelligence and embedded analytics tool. In Metabase Enterprise prior to versions 1.54.22, 1.55.22, 1.56.22, 1.57.16, 1.58.10, and 1.59.4, authenticated admins on Metabase Enterprise Edition can achieve Remote Code Execution (RCE) and Arbitrary File Read via the `POST /api/ee/serialization/import` endpoint. A crafted serialization archive injects an `INIT` property into the H2 JDBC spec, which can execute arbitrary SQL during a database sync. We confirmed this was possible on Metabase Cloud. This only affects Metabase Enterprise. Metabase OSS lacks the affected codepaths. All versions of Metabase Enterprise that have serialization, which dates back to at least version 1.47, are affected. Metabase Enterprise versions 1.54.22, 1.55.22, 1.56.22, 1.57.16, 1.58.10, and 1.59.4 patch the issue. As a workaround, disable the serialization import endpoint in their Metabase instance to prevent access to the vulnerable codepaths.



- [https://github.com/hakaioffsec/CVE-2026-33725](https://github.com/hakaioffsec/CVE-2026-33725) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2026-33725.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2026-33725.svg)

## CVE-2026-33715
 Chamilo LMS is an open-source learning management system. In version 2.0-RC.2, the file public/main/inc/ajax/install.ajax.php is accessible without authentication on fully installed instances because, unlike other AJAX endpoints, it does not include the global.inc.php file that performs authentication and installation-completed checks. Its test_mailer action accepts an arbitrary Symfony Mailer DSN string from POST data and uses it to connect to an attacker-specified SMTP server, enabling Server-Side Request Forgery (SSRF) into internal networks via the SMTP protocol. An unauthenticated attacker can also abuse this to weaponize the Chamilo server as an open email relay for phishing and spam campaigns, with emails appearing to originate from the server's IP address. Additionally, error responses from failed SMTP connections may disclose information about internal network topology and running services. This issue has been fixed in version 2.0.0-RC.3.



- [https://github.com/romain-deperne/CVE-2026-33715](https://github.com/romain-deperne/CVE-2026-33715) :  ![starts](https://img.shields.io/github/stars/romain-deperne/CVE-2026-33715.svg) ![forks](https://img.shields.io/github/forks/romain-deperne/CVE-2026-33715.svg)

## CVE-2026-33701
 OpenTelemetry Java Instrumentation provides OpenTelemetry auto-instrumentation and instrumentation libraries for Java. In versions prior to 2.26.1, the RMI instrumentation registered a custom endpoint that deserialized incoming data without applying serialization filters. On JDK version 16 and earlier, an attacker with network access to a JMX or RMI port on an instrumented JVM could exploit this to potentially achieve remote code execution. All three of the following conditions must be true to exploit this vulnerability: First, OpenTelemetry Java instrumentation is attached as a Java agent (`-javaagent`) on Java 16 or earlier. Second, JMX/RMI port has been explicitly configured via `-Dcom.sun.management.jmxremote.port` and is network-reachable. Third, gadget-chain-compatible library is present on the classpath. This results in arbitrary remote code execution with the privileges of the user running the instrumented JVM. For JDK = 17, no action is required, but upgrading is strongly encouraged. For JDK  17, upgrade to version 2.26.1 or later. As a workaround, set the system property `-Dotel.instrumentation.rmi.enabled=false` to disable the RMI integration.



- [https://github.com/pl4tyz/CVE-2026-33701-Unsafe-Deserialization-in-OpenTelemetry-Java-Agent-RMI-Instrumentation](https://github.com/pl4tyz/CVE-2026-33701-Unsafe-Deserialization-in-OpenTelemetry-Java-Agent-RMI-Instrumentation) :  ![starts](https://img.shields.io/github/stars/pl4tyz/CVE-2026-33701-Unsafe-Deserialization-in-OpenTelemetry-Java-Agent-RMI-Instrumentation.svg) ![forks](https://img.shields.io/github/forks/pl4tyz/CVE-2026-33701-Unsafe-Deserialization-in-OpenTelemetry-Java-Agent-RMI-Instrumentation.svg)

## CVE-2026-33693
 Lemmy is a link aggregator and forum for the fediverse. Prior to version 0.7.0-beta.9, the `v4_is_invalid()` function in `activitypub-federation-rust` (`src/utils.rs`) does not check for `Ipv4Addr::UNSPECIFIED` (0.0.0.0). An unauthenticated attacker controlling a remote domain can point it to 0.0.0.0, bypass the SSRF protection introduced by the fix for CVE-2025-25194 (GHSA-7723-35v7-qcxw), and reach localhost services on the target server. Version 0.7.0-beta.9 patches the issue.



- [https://github.com/SnailSploit/CVE-2026-33693](https://github.com/SnailSploit/CVE-2026-33693) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2026-33693.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2026-33693.svg)

## CVE-2026-33671
 Picomatch is a glob matcher written JavaScript. Versions prior to 4.0.4, 3.0.2, and 2.3.2 are vulnerable to Regular Expression Denial of Service (ReDoS) when processing crafted extglob patterns. Certain patterns using extglob quantifiers such as `+()` and `*()`, especially when combined with overlapping alternatives or nested extglobs, are compiled into regular expressions that can exhibit catastrophic backtracking on non-matching input. Applications are impacted when they allow untrusted users to supply glob patterns that are passed to `picomatch` for compilation or matching. In those cases, an attacker can cause excessive CPU consumption and block the Node.js event loop, resulting in a denial of service. Applications that only use trusted, developer-controlled glob patterns are much less likely to be exposed in a security-relevant way. This issue is fixed in picomatch 4.0.4, 3.0.2 and 2.3.2. Users should upgrade to one of these versions or later, depending on their supported release line. If upgrading is not immediately possible, avoid passing untrusted glob patterns to `picomatch`. Possible mitigations include disabling extglob support for untrusted patterns by using `noextglob: true`, rejecting or sanitizing patterns containing nested extglobs or extglob quantifiers such as `+()` and `*()`, enforcing strict allowlists for accepted pattern syntax, running matching in an isolated worker or separate process with time and resource limits, and applying application-level request throttling and input validation for any endpoint that accepts glob patterns.



- [https://github.com/BeLazy167/next-picomatch-cve-repro](https://github.com/BeLazy167/next-picomatch-cve-repro) :  ![starts](https://img.shields.io/github/stars/BeLazy167/next-picomatch-cve-repro.svg) ![forks](https://img.shields.io/github/forks/BeLazy167/next-picomatch-cve-repro.svg)

## CVE-2026-33656
 EspoCRM is an open source customer relationship management application. Prior to version 9.3.4, EspoCRM's built-in formula scripting engine allowing updating attachment's sourceId thus allowing an authenticated admin to overwrite the `sourceId` field on `Attachment` entities. Because `sourceId` is concatenated directly into a file path with no sanitization in `EspoUploadDir::getFilePath()`, an attacker can redirect any file read or write operation to an arbitrary path within the web server's `open_basedir` scope. Version 9.3.4 fixes the issue.



- [https://github.com/JivaSecurity/ESPOCRM-RCE-POC-CVE-2026-33656](https://github.com/JivaSecurity/ESPOCRM-RCE-POC-CVE-2026-33656) :  ![starts](https://img.shields.io/github/stars/JivaSecurity/ESPOCRM-RCE-POC-CVE-2026-33656.svg) ![forks](https://img.shields.io/github/forks/JivaSecurity/ESPOCRM-RCE-POC-CVE-2026-33656.svg)

## CVE-2026-33634
 Trivy is a security scanner. On March 19, 2026, a threat actor used compromised credentials to publish a malicious Trivy v0.69.4 release, force-push 76 of 77 version tags in `aquasecurity/trivy-action` to credential-stealing malware, and replace all 7 tags in `aquasecurity/setup-trivy` with malicious commits. This incident is a continuation of the supply chain attack that began in late February 2026. Following the initial disclosure on March 1, credential rotation was performed but was not atomic (not all credentials were revoked simultaneously). The attacker could have use a valid token to exfiltrate newly rotated secrets during the rotation window (which lasted a few days). This could have allowed the attacker to retain access and execute the March 19 attack. Affected components include the `aquasecurity/trivy` Go / Container image version 0.69.4, the `aquasecurity/trivy-action` GitHub Action versions 0.0.1 – 0.34.2 (76/77), and the`aquasecurity/setup-trivy` GitHub Action versions 0.2.0 – 0.2.6, prior to the recreation of 0.2.6 with a safe commit. Known safe versions include versions 0.69.2 and 0.69.3 of the Trivy binary, version 0.35.0 of trivy-action, and version 0.2.6 of setup-trivy. Additionally, take other mitigations to ensure the safety of secrets. If there is any possibility that a compromised version ran in one's environment, all secrets accessible to affected pipelines must be treated as exposed and rotated immediately. Check whether one's organization pulled or executed Trivy v0.69.4 from any source. Remove any affected artifacts immediately. Review all workflows using `aquasecurity/trivy-action` or `aquasecurity/setup-trivy`. Those who referenced a version tag rather than a full commit SHA should check workflow run logs from March 19–20, 2026 for signs of compromise. Look for repositories named `tpcp-docs` in one's GitHub organization. The presence of such a repository may indicate that the fallback exfiltration mechanism was triggered and secrets were successfully stolen. Pin GitHub Actions to full, immutable commit SHA hashes, don't use mutable version tags.



- [https://github.com/fevar54/CVE-2026-33634-Scanner](https://github.com/fevar54/CVE-2026-33634-Scanner) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-33634-Scanner.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-33634-Scanner.svg)

- [https://github.com/ugurrates/teampcp-supply-chain-attack](https://github.com/ugurrates/teampcp-supply-chain-attack) :  ![starts](https://img.shields.io/github/stars/ugurrates/teampcp-supply-chain-attack.svg) ![forks](https://img.shields.io/github/forks/ugurrates/teampcp-supply-chain-attack.svg)

- [https://github.com/AshleyT3/docker-socket-risk-demos](https://github.com/AshleyT3/docker-socket-risk-demos) :  ![starts](https://img.shields.io/github/stars/AshleyT3/docker-socket-risk-demos.svg) ![forks](https://img.shields.io/github/forks/AshleyT3/docker-socket-risk-demos.svg)

## CVE-2026-33579
 OpenClaw before 2026.3.28 contains a privilege escalation vulnerability in the /pair approve command path that fails to forward caller scopes into the core approval check. A caller with pairing privileges but without admin privileges can approve pending device requests asking for broader scopes including admin access by exploiting the missing scope validation in extensions/device-pair/index.ts and src/infra/device-pairing.ts.



- [https://github.com/atalovesyou/openclaw-security-checker](https://github.com/atalovesyou/openclaw-security-checker) :  ![starts](https://img.shields.io/github/stars/atalovesyou/openclaw-security-checker.svg) ![forks](https://img.shields.io/github/forks/atalovesyou/openclaw-security-checker.svg)

## CVE-2026-33555
 An issue was discovered in HAProxy before 3.3.6. The HTTP/3 parser does not check that the received body length matches a previously announced content-length when the stream is closed via a frame with an empty payload. This can cause desynchronization issues with the backend server and could be used for request smuggling. The earliest affected version is 2.6.



- [https://github.com/r3verii/CVE-2026-33555](https://github.com/r3verii/CVE-2026-33555) :  ![starts](https://img.shields.io/github/stars/r3verii/CVE-2026-33555.svg) ![forks](https://img.shields.io/github/forks/r3verii/CVE-2026-33555.svg)

## CVE-2026-33534
 EspoCRM is an open source customer relationship management application. Versions 9.3.3 and below have an authenticated Server-Side Request Forgery (SSRF) vulnerability that allows bypassing the internal-host validation logic by using alternative IPv4 representations such as octal notation (e.g., 0177.0.0.1 instead of 127.0.0.1). This is caused by HostCheck::isNotInternalHost() function relying on PHP's filter_var(..., FILTER_VALIDATE_IP), which does not recognize alternative IP formats, causing the validation to fall through to a DNS lookup that returns no records and incorrectly treats the host as safe, however the cURL subsequently normalizes the address and connects to the loopback destination. Through the confirmed /api/v1/Attachment/fromImageUrl endpoint, an authenticated user can force the server to make requests to loopback-only services and store the fetched response as an attachment. This vulnerability is distinct from CVE-2023-46736 (which involved redirect-based SSRF) and may allow access to internal resources reachable from the application runtime. This issue has been fixed in version 9.3.4.



- [https://github.com/EntroVyx/CVE-2026-33534](https://github.com/EntroVyx/CVE-2026-33534) :  ![starts](https://img.shields.io/github/stars/EntroVyx/CVE-2026-33534.svg) ![forks](https://img.shields.io/github/forks/EntroVyx/CVE-2026-33534.svg)

## CVE-2026-33532
 `yaml` is a YAML parser and serialiser for JavaScript. Parsing a YAML document with a version of `yaml` on the 1.x branch prior to 1.10.3 or on the 2.x branch prior to 2.8.3 may throw a RangeError due to a stack overflow. The node resolution/composition phase uses recursive function calls without a depth bound. An attacker who can supply YAML for parsing can trigger a `RangeError: Maximum call stack size exceeded` with a small payload (~2–10 KB). The `RangeError` is not a `YAMLParseError`, so applications that only catch YAML-specific errors will encounter an unexpected exception type. Depending on the host application's exception handling, this can fail requests or terminate the Node.js process. Flow sequences allow deep nesting with minimal bytes (2 bytes per level: one `[` and one `]`). On the default Node.js stack, approximately 1,000–5,000 levels of nesting (2–10 KB input) exhaust the call stack. The exact threshold is environment-dependent (Node.js version, stack size, call stack depth at invocation). Note: the library's `Parser` (CST phase) uses a stack-based iterative approach and is not affected. Only the compose/resolve phase uses actual call-stack recursion. All three public parsing APIs are affected: `YAML.parse()`, `YAML.parseDocument()`, and `YAML.parseAllDocuments()`. Versions 1.10.3 and 2.8.3 contain a patch.



- [https://github.com/danwulff/astro_CVE-2026-33532](https://github.com/danwulff/astro_CVE-2026-33532) :  ![starts](https://img.shields.io/github/stars/danwulff/astro_CVE-2026-33532.svg) ![forks](https://img.shields.io/github/forks/danwulff/astro_CVE-2026-33532.svg)

## CVE-2026-33531
 InvenTree is an Open Source Inventory Management System. Prior to version 1.2.6, a path traversal vulnerability in the report template engine allows a staff-level user to read arbitrary files from the server filesystem via crafted template tags. Affected functions: `encode_svg_image()`, `asset()`, and `uploaded_image()` in `src/backend/InvenTree/report/templatetags/report.py`. This requires staff access (to upload / edit templates with maliciously crafted tags). If the InvenTree installation is configured with high access privileges on the host system, this path traversal may allow file access outside of the InvenTree source directory. This issue is patched in version 1.2.6, and 1.3.0 (or above). Users should update to the patched versions. No known workarounds are available.



- [https://github.com/alonaki/InvenTree-Path-Traversal-CVE-2026-33531](https://github.com/alonaki/InvenTree-Path-Traversal-CVE-2026-33531) :  ![starts](https://img.shields.io/github/stars/alonaki/InvenTree-Path-Traversal-CVE-2026-33531.svg) ![forks](https://img.shields.io/github/forks/alonaki/InvenTree-Path-Traversal-CVE-2026-33531.svg)

## CVE-2026-33453
 Improperly Controlled Modification of Dynamically-Determined Object Attributes vulnerability in Apache Camel Camel-Coap component.

Apache Camel's camel-coap component is vulnerable to Camel message header injection, leading to remote code execution when routes forward CoAP requests to header-sensitive producers (e.g. camel-exec)

The camel-coap component maps incoming CoAP request URI query parameters directly into Camel Exchange In message headers without applying any HeaderFilterStrategy.    
Specifically, CamelCoapResource.handleRequest() iterates over OptionSet.getUriQuery() and calls camelExchange.getIn().setHeader(...) for every query parameter. CoAPEndpoint extends DefaultEndpoint rather than DefaultHeaderFilterStrategyEndpoint, and CoAPComponent does not implement HeaderFilterStrategyComponent; the component contains no references to HeaderFilterStrategy at all.

As a result, an unauthenticated attacker who can send a single CoAP UDP packet to a Camel route consuming from coap:// can inject arbitrary Camel internal headers (those prefixed with Camel*) into the Exchange. When the route delivers the message to a header-sensitive producer such as camel-exec, camel-sql, camel-bean, camel-file, or template components (camel-freemarker, camel-velocity), the injected headers can alter the producer's behavior. In the case of camel-exec, the CamelExecCommandExecutable and CamelExecCommandArgs headers override the executable and arguments configured on the endpoint, resulting in arbitrary OS command execution under the privileges of the Camel process.

The producer's output is written back to the Exchange body and returned in the CoAP response payload by CamelCoapResource, giving the attacker an interactive RCE channel without any need for out-of-band exfiltration.
                                                                                                                                                                         
Exploitation prerequisites are minimal: a single unauthenticated UDP datagram to the CoAP port (default 5683). CoAP (RFC 7252) has no built-in authentication, and DTLS is optional and disabled by default. Because the protocol is UDP-based, HTTP-layer WAF/IDS controls do not apply.
This issue affects Apache Camel: from 4.14.0 through 4.14.5, from 4.18.0 before 4.18.1, 4.19.0.

Users are recommended to upgrade to version 4.18.1 or 4.19.0, fixing the issue.



- [https://github.com/dinosn/CVE-2026-33453](https://github.com/dinosn/CVE-2026-33453) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-33453.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-33453.svg)

## CVE-2026-33439
 Open Access Management (OpenAM) is an access management solution. Prior to 16.0.6, OpenIdentityPlatform OpenAM is vulnerable to pre-authentication Remote Code Execution (RCE) via unsafe Java deserialization of the jato.clientSession HTTP parameter. This bypasses the WhitelistObjectInputStream mitigation that was applied to the jato.pageSession parameter after CVE-2021-35464. An unauthenticated attacker can achieve arbitrary command execution on the server by sending a crafted serialized Java object as the jato.clientSession GET/POST parameter to any JATO ViewBean endpoint whose JSP contains jato:form tags (e.g., the Password Reset pages). This vulnerability is fixed in 16.0.6.



- [https://github.com/TheMalwareGuardian/CVE-2026-33439](https://github.com/TheMalwareGuardian/CVE-2026-33439) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2026-33439.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2026-33439.svg)

- [https://github.com/Ibonok/CVE-2026-33439-PoC](https://github.com/Ibonok/CVE-2026-33439-PoC) :  ![starts](https://img.shields.io/github/stars/Ibonok/CVE-2026-33439-PoC.svg) ![forks](https://img.shields.io/github/forks/Ibonok/CVE-2026-33439-PoC.svg)

- [https://github.com/shreyas-malhotra/CVE-2026-33439-OpenAM](https://github.com/shreyas-malhotra/CVE-2026-33439-OpenAM) :  ![starts](https://img.shields.io/github/stars/shreyas-malhotra/CVE-2026-33439-OpenAM.svg) ![forks](https://img.shields.io/github/forks/shreyas-malhotra/CVE-2026-33439-OpenAM.svg)

## CVE-2026-33340
 LoLLMs WEBUI provides the Web user interface for Lord of Large Language and Multi modal Systems. A critical Server-Side Request Forgery (SSRF) vulnerability has been identified in all known existing versions of `lollms-webui`. The `@router.post("/api/proxy")` endpoint allows unauthenticated attackers to force the server into making arbitrary GET requests. This can be exploited to access internal services, scan local networks, or exfiltrate sensitive cloud metadata (e.g., AWS/GCP IAM tokens). As of time of publication, no known patched versions are available.



- [https://github.com/regaan/CVE-2026-33340](https://github.com/regaan/CVE-2026-33340) :  ![starts](https://img.shields.io/github/stars/regaan/CVE-2026-33340.svg) ![forks](https://img.shields.io/github/forks/regaan/CVE-2026-33340.svg)

## CVE-2026-33331
 oRPC is an tool that helps build APIs that are end-to-end type-safe and adhere to OpenAPI standards. Prior to version 1.13.9, a stored cross-site scripting (XSS) vulnerability exists in the OpenAPI documentation generation of orpc. If an attacker can control any field within the OpenAPI specification (such as info.description), they can break out of the JSON context and execute arbitrary JavaScript when a user views the generated API documentation. This issue has been patched in version 1.13.9.



- [https://github.com/abhayclasher/CVE-2026-33331](https://github.com/abhayclasher/CVE-2026-33331) :  ![starts](https://img.shields.io/github/stars/abhayclasher/CVE-2026-33331.svg) ![forks](https://img.shields.io/github/forks/abhayclasher/CVE-2026-33331.svg)

## CVE-2026-33324
 SQLBot is an intelligent Text-to-SQL system based on large language models and RAG. In versions 1.7.0 and earlier, the Text2SQL chat interface is vulnerable to prompt injection. The user-provided question parameter is directly concatenated into the LLM prompt without filtering or escaping, and the SQL extracted from the LLM response is executed against the database without validation or sanitization. An authenticated attacker can craft a malicious question to manipulate the LLM into generating and executing arbitrary SQL statements. When connected to a PostgreSQL data source, this can lead to remote code execution via COPY FROM PROGRAM. This issue has been fixed in version 1.7.1.



- [https://github.com/CryptReaper12/CVE-2026-33324](https://github.com/CryptReaper12/CVE-2026-33324) :  ![starts](https://img.shields.io/github/stars/CryptReaper12/CVE-2026-33324.svg) ![forks](https://img.shields.io/github/forks/CryptReaper12/CVE-2026-33324.svg)

## CVE-2026-33320
 Dasel is a command-line tool and library for querying, modifying, and transforming data structures. Starting in version 3.0.0 and prior to version 3.3.1, Dasel's YAML reader allows an attacker who can supply YAML for processing to trigger extreme CPU and memory consumption. The issue is in the library's own `UnmarshalYAML` implementation, which manually resolves alias nodes by recursively following `yaml.Node.Alias` pointers without any expansion budget, bypassing go-yaml v4's built-in alias expansion limit. Version 3.3.2 contains a patch for the issue.



- [https://github.com/nedlir/dasel-hardened-container](https://github.com/nedlir/dasel-hardened-container) :  ![starts](https://img.shields.io/github/stars/nedlir/dasel-hardened-container.svg) ![forks](https://img.shields.io/github/forks/nedlir/dasel-hardened-container.svg)

## CVE-2026-33317
 OP-TEE is a Trusted Execution Environment (TEE) designed as companion to a non-secure Linux kernel running on Arm; Cortex-A cores using the TrustZone technology. In versions 3.13.0 through 4.10.0, missing checks in `entry_get_attribute_value()`  in `ta/pkcs11/src/object.c` can lead to out-of-bounds read from the PKCS#11 TA heap or a crash. When chained with the OOB read, the PKCS#11 TA function `PKCS11_CMD_GET_ATTRIBUTE_VALUE`  or `entry_get_attribute_value()` can, with a bad template parameter, be tricked into reading at most 7 bytes beyond the end of the template buffer and writing beyond the end of the template buffer with the content of an attribute value of a PKCS#11 object. Commits e031c4e562023fd9f199e39fd2e85797e4cbdca9, 16926d5a46934c46e6656246b4fc18385a246900, and 149e8d7ecc4ef8bb00ab4a37fd2ccede6d79e1ca contain patches and are anticipated to be part of version 4.11.0.



- [https://github.com/qianfei11/CVE-2026-33317](https://github.com/qianfei11/CVE-2026-33317) :  ![starts](https://img.shields.io/github/stars/qianfei11/CVE-2026-33317.svg) ![forks](https://img.shields.io/github/forks/qianfei11/CVE-2026-33317.svg)

## CVE-2026-33310
 Intake is a package for finding, investigating, loading and disseminating data. Prior to version 2.0.9, the shell() syntax within parameter default values appears to be automatically expanded during the catalog parsing process. If a catalog contains a parameter default such as shell(command), the command may be executed when the catalog source is accessed. This means that if a user loads a malicious catalog YAML, embedded commands could execute on the host system. Version 2.0.9 mitigates the issue by making getshell False by default everywhere.



- [https://github.com/redyank/CVE-2026-33310](https://github.com/redyank/CVE-2026-33310) :  ![starts](https://img.shields.io/github/stars/redyank/CVE-2026-33310.svg) ![forks](https://img.shields.io/github/forks/redyank/CVE-2026-33310.svg)

## CVE-2026-33229
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Prior to 17.4.8 and 17.10.1, an improperly protected scripting API allows any user with script right to bypass the sandboxing of the Velocity scripting API and execute, e.g., arbitrary Python scripts, allowing full access to the XWiki instance and thereby compromising the confidentiality, integrity and availability of the whole instance. Note that script right already constitutes a high level of access that we don't recommend giving to untrusted users. This vulnerability is fixed in 17.4.8 and 17.10.1.



- [https://github.com/azefzafyoussef/CVE-2026-33229](https://github.com/azefzafyoussef/CVE-2026-33229) :  ![starts](https://img.shields.io/github/stars/azefzafyoussef/CVE-2026-33229.svg) ![forks](https://img.shields.io/github/forks/azefzafyoussef/CVE-2026-33229.svg)

## CVE-2026-33186
 gRPC-Go is the Go language implementation of gRPC. Versions prior to 1.79.3 have an authorization bypass resulting from improper input validation of the HTTP/2 `:path` pseudo-header. The gRPC-Go server was too lenient in its routing logic, accepting requests where the `:path` omitted the mandatory leading slash (e.g., `Service/Method` instead of `/Service/Method`). While the server successfully routed these requests to the correct handler, authorization interceptors (including the official `grpc/authz` package) evaluated the raw, non-canonical path string. Consequently, "deny" rules defined using canonical paths (starting with `/`) failed to match the incoming request, allowing it to bypass the policy if a fallback "allow" rule was present. This affects gRPC-Go servers that use path-based authorization interceptors, such as the official RBAC implementation in `google.golang.org/grpc/authz` or custom interceptors relying on `info.FullMethod` or `grpc.Method(ctx)`; AND that have a security policy contains specific "deny" rules for canonical paths but allows other requests by default (a fallback "allow" rule). The vulnerability is exploitable by an attacker who can send raw HTTP/2 frames with malformed `:path` headers directly to the gRPC server. The fix in version 1.79.3 ensures that any request with a `:path` that does not start with a leading slash is immediately rejected with a `codes.Unimplemented` error, preventing it from reaching authorization interceptors or handlers with a non-canonical path string. While upgrading is the most secure and recommended path, users can mitigate the vulnerability using one of the following methods: Use a validating interceptor (recommended mitigation); infrastructure-level normalization; and/or policy hardening.



- [https://github.com/JohannesLks/CVE-2026-33186](https://github.com/JohannesLks/CVE-2026-33186) :  ![starts](https://img.shields.io/github/stars/JohannesLks/CVE-2026-33186.svg) ![forks](https://img.shields.io/github/forks/JohannesLks/CVE-2026-33186.svg)

## CVE-2026-33179
 libfuse is the reference implementation of the Linux FUSE. From version 3.18.0 to before version 3.18.2, a NULL pointer dereference and memory leak in fuse_uring_init_queue allows a local user to crash the FUSE daemon or cause resource exhaustion. When numa_alloc_local fails during io_uring queue entry setup, the code proceeds with NULL pointers. When fuse_uring_register_queue fails, NUMA allocations are leaked and the function incorrectly returns success. Only the io_uring transport is affected; the traditional /dev/fuse path is not affected. PoC confirmed with AddressSanitizer/LeakSanitizer. This issue has been patched in version 3.18.2.



- [https://github.com/abhinavagarwal07/abhinavagarwal07.github.io](https://github.com/abhinavagarwal07/abhinavagarwal07.github.io) :  ![starts](https://img.shields.io/github/stars/abhinavagarwal07/abhinavagarwal07.github.io.svg) ![forks](https://img.shields.io/github/forks/abhinavagarwal07/abhinavagarwal07.github.io.svg)

## CVE-2026-33154
 dynaconf is a configuration management tool for Python. Prior to version 3.2.13, Dynaconf is vulnerable to Server-Side Template Injection (SSTI) due to unsafe template evaluation in the @Jinja resolver. When the jinja2 package is installed, Dynaconf evaluates template expressions embedded in configuration values without a sandboxed environment. This issue has been patched in version 3.2.13.



- [https://github.com/redyank/CVE-2026-33154](https://github.com/redyank/CVE-2026-33154) :  ![starts](https://img.shields.io/github/stars/redyank/CVE-2026-33154.svg) ![forks](https://img.shields.io/github/forks/redyank/CVE-2026-33154.svg)

## CVE-2026-33150
 libfuse is the reference implementation of the Linux FUSE. From version 3.18.0 to before version 3.18.2, a use-after-free vulnerability in the io_uring subsystem of libfuse allows a local attacker to crash FUSE filesystem processes and potentially execute arbitrary code. When io_uring thread creation fails due to resource exhaustion (e.g., cgroup pids.max), fuse_uring_start() frees the ring pool structure but stores the dangling pointer in the session state, leading to a use-after-free when the session shuts down. The trigger is reliable in containerized environments where cgroup pids.max limits naturally constrain thread creation. This issue has been patched in version 3.18.2.



- [https://github.com/abhinavagarwal07/abhinavagarwal07.github.io](https://github.com/abhinavagarwal07/abhinavagarwal07.github.io) :  ![starts](https://img.shields.io/github/stars/abhinavagarwal07/abhinavagarwal07.github.io.svg) ![forks](https://img.shields.io/github/forks/abhinavagarwal07/abhinavagarwal07.github.io.svg)

## CVE-2026-33149
 Tandoor Recipes is an application for managing recipes, planning meals, and building shopping lists. Versions up to and including 2.5.3 set ALLOWED_HOSTS = '*' by default, which causes Django to accept any value in the HTTP Host header without validation. The application uses request.build_absolute_uri() to generate absolute URLs in multiple contexts, including invite link emails, API pagination, and OpenAPI schema generation. An attacker who can send requests to the application with a crafted Host header can manipulate all server-generated absolute URLs. The most critical impact is invite link poisoning: when an admin creates an invite and the application sends the invite email, the link points to the attacker's server instead of the real application. When the victim clicks the link, the invite token is sent to the attacker, who can then use it at the real application. As of time of publication, it is unknown if a patched version is available.



- [https://github.com/FilipeGaudard/CVE-2026-33149-PoC](https://github.com/FilipeGaudard/CVE-2026-33149-PoC) :  ![starts](https://img.shields.io/github/stars/FilipeGaudard/CVE-2026-33149-PoC.svg) ![forks](https://img.shields.io/github/forks/FilipeGaudard/CVE-2026-33149-PoC.svg)

## CVE-2026-33147
 GMT is an open source collection of command-line tools for manipulating geographic and Cartesian data sets. In versions from 6.6.0 and prior, a stack-based buffer overflow vulnerability was identified in the gmt_remote_dataset_id function within src/gmt_remote.c. This issue occurs when a specially crafted long string is passed as a dataset identifier (e.g., via the which module), leading to a crash or potential arbitrary code execution. This issue has been patched via commit 0ad2b49.



- [https://github.com/redyank/CVE-2026-33147](https://github.com/redyank/CVE-2026-33147) :  ![starts](https://img.shields.io/github/stars/redyank/CVE-2026-33147.svg) ![forks](https://img.shields.io/github/forks/redyank/CVE-2026-33147.svg)

## CVE-2026-33033
 An issue was discovered in 6.0 before 6.0.4, 5.2 before 5.2.13, and 4.2 before 4.2.30.
`MultiPartParser` allows remote attackers to degrade performance by submitting multipart uploads with `Content-Transfer-Encoding: base64` including excessive whitespace.
Earlier, unsupported Django series (such as 5.0.x, 4.1.x, and 3.2.x) were not evaluated and may also be affected.
Django would like to thank Seokchan Yoon for reporting this issue.



- [https://github.com/ch4n3-yoon/CVE-2026-33033-PoC](https://github.com/ch4n3-yoon/CVE-2026-33033-PoC) :  ![starts](https://img.shields.io/github/stars/ch4n3-yoon/CVE-2026-33033-PoC.svg) ![forks](https://img.shields.io/github/forks/ch4n3-yoon/CVE-2026-33033-PoC.svg)

## CVE-2026-33032
 Nginx UI is a web user interface for the Nginx web server. In versions 2.3.5 and prior, the nginx-ui MCP (Model Context Protocol) integration exposes two HTTP endpoints: /mcp and /mcp_message. While /mcp requires both IP whitelisting and authentication (AuthRequired() middleware), the /mcp_message endpoint only applies IP whitelisting - and the default IP whitelist is empty, which the middleware treats as "allow all". This means any network attacker can invoke all MCP tools without authentication, including restarting nginx, creating/modifying/deleting nginx configuration files, and triggering automatic config reloads - achieving complete nginx service takeover. At time of publication, there are no publicly available patches.



- [https://github.com/Twinson333/cve-2026-33032-scanner](https://github.com/Twinson333/cve-2026-33032-scanner) :  ![starts](https://img.shields.io/github/stars/Twinson333/cve-2026-33032-scanner.svg) ![forks](https://img.shields.io/github/forks/Twinson333/cve-2026-33032-scanner.svg)

- [https://github.com/keraattin/CVE-2026-33032](https://github.com/keraattin/CVE-2026-33032) :  ![starts](https://img.shields.io/github/stars/keraattin/CVE-2026-33032.svg) ![forks](https://img.shields.io/github/forks/keraattin/CVE-2026-33032.svg)

- [https://github.com/Shreda/CVE-2026-33032-nginx-ui-vuln-lab](https://github.com/Shreda/CVE-2026-33032-nginx-ui-vuln-lab) :  ![starts](https://img.shields.io/github/stars/Shreda/CVE-2026-33032-nginx-ui-vuln-lab.svg) ![forks](https://img.shields.io/github/forks/Shreda/CVE-2026-33032-nginx-ui-vuln-lab.svg)

## CVE-2026-33017
 Langflow is a tool for building and deploying AI-powered agents and workflows. In versions prior to 1.9.0, the POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication. When the optional data parameter is supplied, the endpoint uses attacker-controlled flow data (containing arbitrary Python code in node definitions) instead of the stored flow data from the database. This code is passed to exec() with zero sandboxing, resulting in unauthenticated remote code execution. This is distinct from CVE-2025-3248, which fixed /api/v1/validate/code by adding authentication. The build_public_tmp endpoint is designed to be unauthenticated (for public flows) but incorrectly accepts attacker-supplied flow data containing arbitrary executable code. This issue has been fixed in version 1.9.0.



- [https://github.com/MaxMnMl/langflow-CVE-2026-33017-poc](https://github.com/MaxMnMl/langflow-CVE-2026-33017-poc) :  ![starts](https://img.shields.io/github/stars/MaxMnMl/langflow-CVE-2026-33017-poc.svg) ![forks](https://img.shields.io/github/forks/MaxMnMl/langflow-CVE-2026-33017-poc.svg)

- [https://github.com/EQSTLab/CVE-2026-33017](https://github.com/EQSTLab/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-33017.svg)

- [https://github.com/z4yd3/PoC-CVE-2026-33017](https://github.com/z4yd3/PoC-CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/z4yd3/PoC-CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/z4yd3/PoC-CVE-2026-33017.svg)

- [https://github.com/Jorrit-VM/CVE-2026-33017](https://github.com/Jorrit-VM/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/Jorrit-VM/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/Jorrit-VM/CVE-2026-33017.svg)

- [https://github.com/omer-efe-curkus/CVE-2026-33017-Langflow-RCE-PoC](https://github.com/omer-efe-curkus/CVE-2026-33017-Langflow-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/omer-efe-curkus/CVE-2026-33017-Langflow-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/omer-efe-curkus/CVE-2026-33017-Langflow-RCE-PoC.svg)

- [https://github.com/0xBlackash/CVE-2026-33017](https://github.com/0xBlackash/CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-33017.svg)

- [https://github.com/oscar-mine/CVE-2026-33017-Exploit](https://github.com/oscar-mine/CVE-2026-33017-Exploit) :  ![starts](https://img.shields.io/github/stars/oscar-mine/CVE-2026-33017-Exploit.svg) ![forks](https://img.shields.io/github/forks/oscar-mine/CVE-2026-33017-Exploit.svg)

- [https://github.com/rootdirective-sec/CVE-2026-33017-Lab](https://github.com/rootdirective-sec/CVE-2026-33017-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-33017-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-33017-Lab.svg)

- [https://github.com/masterwok/PoC-CVE-2026-33017](https://github.com/masterwok/PoC-CVE-2026-33017) :  ![starts](https://img.shields.io/github/stars/masterwok/PoC-CVE-2026-33017.svg) ![forks](https://img.shields.io/github/forks/masterwok/PoC-CVE-2026-33017.svg)

- [https://github.com/SimoesCTT/Sovereign-Echo-33017](https://github.com/SimoesCTT/Sovereign-Echo-33017) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/Sovereign-Echo-33017.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/Sovereign-Echo-33017.svg)

## CVE-2026-33006
 A timing attack against mod_auth_digest in Apache HTTP Server 2.4.66 allows a bypass of Digest authentication by a remote attacker.

Users are recommended to upgrade to version 2.4.67, which fixes this issue.



- [https://github.com/SimoesCTT/CTT-enhanced-Apache-mod_auth_digest-timing-attack-exploit](https://github.com/SimoesCTT/CTT-enhanced-Apache-mod_auth_digest-timing-attack-exploit) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-enhanced-Apache-mod_auth_digest-timing-attack-exploit.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-enhanced-Apache-mod_auth_digest-timing-attack-exploit.svg)

## CVE-2026-32945
 PJSIP is a free and open source multimedia communication library written in C. Versions 2.16 and below have a Heap-based Buffer Overflowvulnerability in the DNS parser's name length handler. Thisimpacts applications using PJSIP's built-in DNS resolver, such as those configured with pjsua_config.nameserver or UaConfig.nameserver in PJSUA/PJSUA2. It does not affect users who rely on the OS resolver (e.g., getaddrinfo()) by not configuring a nameserver, or those using an external resolver via pjsip_resolver_set_ext_resolver(). This issue is fixed in version 2.17. For users unable to upgrade, a workaround is to disable DNS resolution in the PJSIP config (by setting nameserver_count to zero) or to use an external resolver implementation instead.



- [https://github.com/JohannesLks/CVE-2026-32945](https://github.com/JohannesLks/CVE-2026-32945) :  ![starts](https://img.shields.io/github/stars/JohannesLks/CVE-2026-32945.svg) ![forks](https://img.shields.io/github/forks/JohannesLks/CVE-2026-32945.svg)

## CVE-2026-32941
 Sliver is a command and control framework that uses a custom Wireguard netstack. Versions 1.7.3 and below contain a Remote OOM (Out-of-Memory) vulnerability in the Sliver C2 server's mTLS and WireGuard C2 transport layer. The socketReadEnvelope and socketWGReadEnvelope functions trust an attacker-controlled 4-byte length prefix to allocate memory, with ServerMaxMessageSize allowing single allocations of up to ~2 GiB. A compromised implant or an attacker with valid credentials can exploit this by sending fabricated length prefixes over concurrent yamux streams (up to 128 per connection), forcing the server to attempt allocating ~256 GiB of memory and triggering an OS OOM kill. This crashes the Sliver server, disrupts all active implant sessions, and may degrade or kill other processes sharing the same host. The same pattern also affects all implant-side readers, which have no upper-bound check at all. The issue was not fixed at the the time of publication.



- [https://github.com/skoveit/CVE-2026-32941](https://github.com/skoveit/CVE-2026-32941) :  ![starts](https://img.shields.io/github/stars/skoveit/CVE-2026-32941.svg) ![forks](https://img.shields.io/github/forks/skoveit/CVE-2026-32941.svg)

## CVE-2026-32913
 OpenClaw before 2026.3.7 contains an improper header validation vulnerability in fetchWithSsrFGuard that forwards custom authorization headers across cross-origin redirects. Attackers can trigger redirects to different origins to intercept sensitive headers like X-Api-Key and Private-Token intended for the original destination.



- [https://github.com/Rickidevs/CVE-2026-32913](https://github.com/Rickidevs/CVE-2026-32913) :  ![starts](https://img.shields.io/github/stars/Rickidevs/CVE-2026-32913.svg) ![forks](https://img.shields.io/github/forks/Rickidevs/CVE-2026-32913.svg)

## CVE-2026-32794
 Improper Certificate Validation vulnerability in Apache Airflow Provider for Databricks. Provider code did not validate certificates for connections to Databricks back-end which could result in a man-of-a-middle attack that traffic is intercepted and manipulated or credentials exfiltrated w/o notice.

This issue affects Apache Airflow Provider for Databricks: from 1.10.0 before 1.12.0.

Users are recommended to upgrade to version 1.12.0, which fixes the issue.



- [https://github.com/SnailSploit/CVE-2026-32794](https://github.com/SnailSploit/CVE-2026-32794) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2026-32794.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2026-32794.svg)

## CVE-2026-32746
 telnetd in GNU inetutils through 2.7 allows an out-of-bounds write in the LINEMODE SLC (Set Local Characters) suboption handler because add_slc does not check whether the buffer is full.



- [https://github.com/jeffaf/cve-2026-32746](https://github.com/jeffaf/cve-2026-32746) :  ![starts](https://img.shields.io/github/stars/jeffaf/cve-2026-32746.svg) ![forks](https://img.shields.io/github/forks/jeffaf/cve-2026-32746.svg)

- [https://github.com/watchtowrlabs/watchtowr-vs-telnetd-CVE-2026-32746](https://github.com/watchtowrlabs/watchtowr-vs-telnetd-CVE-2026-32746) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchtowr-vs-telnetd-CVE-2026-32746.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchtowr-vs-telnetd-CVE-2026-32746.svg)

- [https://github.com/ekomsSavior/telnet_scan](https://github.com/ekomsSavior/telnet_scan) :  ![starts](https://img.shields.io/github/stars/ekomsSavior/telnet_scan.svg) ![forks](https://img.shields.io/github/forks/ekomsSavior/telnet_scan.svg)

- [https://github.com/kaleth4/CVE-2026-32746](https://github.com/kaleth4/CVE-2026-32746) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-32746.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-32746.svg)

- [https://github.com/chosenonehacks/CVE-2026-32746](https://github.com/chosenonehacks/CVE-2026-32746) :  ![starts](https://img.shields.io/github/stars/chosenonehacks/CVE-2026-32746.svg) ![forks](https://img.shields.io/github/forks/chosenonehacks/CVE-2026-32746.svg)

- [https://github.com/danindiana/cve-2026-32746-mitigation](https://github.com/danindiana/cve-2026-32746-mitigation) :  ![starts](https://img.shields.io/github/stars/danindiana/cve-2026-32746-mitigation.svg) ![forks](https://img.shields.io/github/forks/danindiana/cve-2026-32746-mitigation.svg)

- [https://github.com/duduLiu8787/CVE-2026-32746-Exploit](https://github.com/duduLiu8787/CVE-2026-32746-Exploit) :  ![starts](https://img.shields.io/github/stars/duduLiu8787/CVE-2026-32746-Exploit.svg) ![forks](https://img.shields.io/github/forks/duduLiu8787/CVE-2026-32746-Exploit.svg)

## CVE-2026-32743
 PX4 is an open-source autopilot stack for drones and unmanned vehicles. Versions 1.17.0-rc2 and below are vulnerable to Stack-based Buffer Overflow through the MavlinkLogHandler, and are triggered via MAVLink log request. The LogEntry.filepath buffer is 60 bytes, but the sscanf function parses paths from the log list file with no width specifier, allowing a path longer than 60 characters to overflow the buffer. An attacker with MAVLink link access can trigger this by first creating deeply nested directories via MAVLink FTP, then requesting the log list. The flight controller MAVLink task crashes, losing telemetry and command capability and causing DoS. This issue has been fixed in this commit: https://github.com/PX4/PX4-Autopilot/commit/616b25a280e229c24d5cf12a03dbf248df89c474.



- [https://github.com/SimoesCTT/CTT-Enhanced-PX4-Autopilot-Exploit-CVE-2026-32743](https://github.com/SimoesCTT/CTT-Enhanced-PX4-Autopilot-Exploit-CVE-2026-32743) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Enhanced-PX4-Autopilot-Exploit-CVE-2026-32743.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Enhanced-PX4-Autopilot-Exploit-CVE-2026-32743.svg)

- [https://github.com/mbanyamer/CVE-2026-32743-PX4-Autopilot-MavlinkLogHandler-Stack-Buffer-Overflow-DoS-](https://github.com/mbanyamer/CVE-2026-32743-PX4-Autopilot-MavlinkLogHandler-Stack-Buffer-Overflow-DoS-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-32743-PX4-Autopilot-MavlinkLogHandler-Stack-Buffer-Overflow-DoS-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-32743-PX4-Autopilot-MavlinkLogHandler-Stack-Buffer-Overflow-DoS-.svg)

## CVE-2026-32731
 ApostropheCMS is an open-source content management framework. Prior to version 3.5.3 of `@apostrophecms/import-export`,
The `extract()` function in `gzip.js` constructs file-write paths using `fs.createWriteStream(path.join(exportPath, header.name))`. `path.join()` does not resolve or sanitise traversal segments such as `../`. It concatenates them as-is, meaning a tar entry named `../../evil.js` resolves to a path outside the intended extraction directory. No canonical-path check is performed before the write stream is opened. This is a textbook Zip Slip vulnerability. Any user who has been granted the Global Content Modify permission — a role routinely assigned to content editors and site managers — can upload a crafted `.tar.gz` file through the standard CMS import UI and write attacker-controlled content to any path the Node.js process can reach on the host filesystem. Version 3.5.3 of `@apostrophecms/import-export` fixes the issue.



- [https://github.com/0xEr3n/CVE-2026-32731](https://github.com/0xEr3n/CVE-2026-32731) :  ![starts](https://img.shields.io/github/stars/0xEr3n/CVE-2026-32731.svg) ![forks](https://img.shields.io/github/forks/0xEr3n/CVE-2026-32731.svg)

## CVE-2026-32722
 Memray is a memory profiler for Python. Prior to Memray 1.19.2, Memray rendered the command line of the tracked process directly into generated HTML reports without escaping. Because there was no escaping, attacker-controlled command line arguments were inserted as raw HTML into the generated report. This allowed JavaScript execution when a victim opened the generated report in a browser. Version 1.19.2 fixes the issue.



- [https://github.com/0xmrma/CVE-2026-32722](https://github.com/0xmrma/CVE-2026-32722) :  ![starts](https://img.shields.io/github/stars/0xmrma/CVE-2026-32722.svg) ![forks](https://img.shields.io/github/forks/0xmrma/CVE-2026-32722.svg)

## CVE-2026-32710
 MariaDB server is a community developed fork of MySQL server. An authenticated user can crash MariaDB versions 11.4 before 11.4.10 and 11.8 before 11.8.6 via a bug in JSON_SCHEMA_VALID() function. Under certain conditions it might be possible to turn the crash into a remote code execution. These conditions require tight control over memory layout which is generally only attainable in a lab environment. This issue is fixed in MariaDB 11.4.10, MariaDB 11.8.6, and MariaDB 12.2.2.



- [https://github.com/dinosn/CVE-2026-32710](https://github.com/dinosn/CVE-2026-32710) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-32710.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-32710.svg)

## CVE-2026-32707
 PX4 autopilot is a flight control solution for drones. Prior to 1.17.0-rc2, tattu_can contains an unbounded memcpy in its multi-frame assembly loop, allowing stack memory overwrite when crafted CAN frames are processed. In deployments where tattu_can is enabled and running, a CAN-injection-capable attacker can trigger a crash (DoS) and memory corruption. This vulnerability is fixed in 1.17.0-rc2.



- [https://github.com/mbanyamer/CVE-2026-32707-PX4-Autopilot-tattu_can-Stack-Buffer-Overflow-DoS-](https://github.com/mbanyamer/CVE-2026-32707-PX4-Autopilot-tattu_can-Stack-Buffer-Overflow-DoS-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-32707-PX4-Autopilot-tattu_can-Stack-Buffer-Overflow-DoS-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-32707-PX4-Autopilot-tattu_can-Stack-Buffer-Overflow-DoS-.svg)

## CVE-2026-32699
 FacturaScripts is an open source accounting and invoicing software. In versions 2025.92 and earlier, the application fails to validate the nick parameter during a POST request to the EditUser controller. Although the user interface prevents editing this field, a user can bypass this restriction by intercepting the request and modifying the nick form-data parameter to rename any account, including the administrator account. This leads to unauthorized modification of a field intended to be immutable.



- [https://github.com/TurkiOS/cve-2026-32699-facturascripts-nick-bypass](https://github.com/TurkiOS/cve-2026-32699-facturascripts-nick-bypass) :  ![starts](https://img.shields.io/github/stars/TurkiOS/cve-2026-32699-facturascripts-nick-bypass.svg) ![forks](https://img.shields.io/github/forks/TurkiOS/cve-2026-32699-facturascripts-nick-bypass.svg)

## CVE-2026-32662
 Development and test API endpoints are present that mirror production functionality.



- [https://github.com/MichaelAdamGroberman/CVE-2026-32662](https://github.com/MichaelAdamGroberman/CVE-2026-32662) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2026-32662.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2026-32662.svg)

## CVE-2026-32646
 A specific administrative endpoint is accessible without proper authentication, exposing device management functions.



- [https://github.com/MichaelAdamGroberman/CVE-2026-32646](https://github.com/MichaelAdamGroberman/CVE-2026-32646) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2026-32646.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2026-32646.svg)

## CVE-2026-32613
 Spinnaker is an open source, multi-cloud continuous delivery platform. Echo like some other services, uses SPeL (Spring Expression Language) to process information - specifically around expected artifacts. In versions prior to 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2, unlike orca, it was NOT restricting that context to a set of trusted classes, but allowing FULL JVM access. This enabled a user to use arbitrary java classes which allow deep access to the system. This enabled the ability to invoke commands, access files, etc. Versions 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2 contain a patch. As a workaround, disable echo entirely.



- [https://github.com/ZeroPathAI/spinnaker-poc](https://github.com/ZeroPathAI/spinnaker-poc) :  ![starts](https://img.shields.io/github/stars/ZeroPathAI/spinnaker-poc.svg) ![forks](https://img.shields.io/github/forks/ZeroPathAI/spinnaker-poc.svg)

## CVE-2026-32606
 IncusOS is an immutable OS image dedicated to running Incus. Prior to 202603142010, the default configuration of systemd-cryptenroll as used by IncusOS through mkosi allows for an attacker with physical access to the machine to access the encrypted data without requiring any interaction by the system's owner or any tampering of Secure Boot state or kernel (UKI) boot image. That's because in this configuration, the LUKS key is made available by the TPM so long as the system has the expected PCR7 value and the PCR11 policy matches. That default PCR11 policy importantly allows for the TPM to release the key to the booted system rather than just from the initrd part of the signed kernel image (UKI). The attack relies on the attacker being able to substitute the original encrypted root partition for one that they control. By doing so, the system will prompt for a recovery key on boot, which the attacker has defined and can provide, before booting the system using the attacker's root partition rather than the system's original one. The attacker only needs to put a systemd unit starting on system boot within their root partition to have the system run that logic on boot. That unit will then run in an environment where the TPM will allow for the retrieval of the encryption key of the real root disk, allowing the attacker to steal the LUKS volume key (immutable master key) and then use it against the real root disk, altering it or getting data out before putting the disk back the way it was and returning the system without a trace of this attack having happened. This is all possible because the system will have still booted with Secure Boot enabled, will have measured and ran the expected bootloader and kernel image (UKI). The initrd selects the root disk based on GPT partition identifiers making it possible to easily substitute the real root disk for an attacker controlled one. This doesn't lead to any change in the TPM state and therefore allows for retrieval of the LUKS key by the attacker through a boot time systemd unit on their alternative root partition. IncusOS version 202603142010 (2026/03/14 20:10 UTC)  includes the new PCR15 logic and will automatically update the TPM policy on boot. Anyone suspecting that their system may have been physically accessed while shut down should perform a full system wipe and reinstallation as only that will rotate the LUKS volume key and prevent subsequent access to the encrypted data should the system have been previously compromised. There are no known workarounds other than updating to a version with corrected logic which will automatically rebind the LUKS keys to the new set of TPM registers and prevent this from being exploited.



- [https://github.com/gibmat/CVE-2026-32606-POC](https://github.com/gibmat/CVE-2026-32606-POC) :  ![starts](https://img.shields.io/github/stars/gibmat/CVE-2026-32606-POC.svg) ![forks](https://img.shields.io/github/forks/gibmat/CVE-2026-32606-POC.svg)

## CVE-2026-32604
 Spinnaker is an open source, multi-cloud continuous delivery platform. In versions prior to 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2, a bad actor can execute arbitrary commands very simply on the clouddriver pods. This can expose credentials, remove files, or inject resources easily. Versions 2026.1.0, 2026.0.1, 2025.4.2, and 2025.3.2 contain a patch. As a workaround, disable the gitrepo artifact types.



- [https://github.com/ZeroPathAI/spinnaker-poc](https://github.com/ZeroPathAI/spinnaker-poc) :  ![starts](https://img.shields.io/github/stars/ZeroPathAI/spinnaker-poc.svg) ![forks](https://img.shields.io/github/forks/ZeroPathAI/spinnaker-poc.svg)

## CVE-2026-32321
 ClipBucket v5 is an open source video sharing platform. An authenticated time-based blind SQL injection vulnerability exists in ClipBucket prior to 5.5.3 #80 within the `actions/ajax.php` endpoint. Due to insufficient input sanitization of the `userid` parameter, an authenticated attacker can execute arbitrary SQL queries, leading to full database disclosure and potential administrative account takeover. Version 5.5.3 #80 fixes the issue.



- [https://github.com/drkim-dev/CVE-2026-32321](https://github.com/drkim-dev/CVE-2026-32321) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-32321.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-32321.svg)

## CVE-2026-32286
 The DataRow.Decode function fails to properly validate field lengths. A malicious or compromised PostgreSQL server can send a DataRow message with a negative field length, causing a slice bounds out of range panic.



- [https://github.com/moisei-dev/go-dbmigrate](https://github.com/moisei-dev/go-dbmigrate) :  ![starts](https://img.shields.io/github/stars/moisei-dev/go-dbmigrate.svg) ![forks](https://img.shields.io/github/forks/moisei-dev/go-dbmigrate.svg)

## CVE-2026-32255
 Kan is an open-source project management tool. In versions 0.5.4 and below, the /api/download/attatchment endpoint has no authentication and no URL validation. The Attachment Download endpoint accepts a user-supplied URL query parameter and passes it directly to fetch() server-side, and returns the full response body. An unauthenticated attacker can use this to make HTTP requests from the server to internal services, cloud metadata endpoints, or private network resources. This issue has been fixed in version 0.5.5. To workaround this issue, block or restrict access to /api/download/attatchment at the reverse proxy level (nginx, Cloudflare, etc.).



- [https://github.com/kOaDT/poc-cve-2026-32255](https://github.com/kOaDT/poc-cve-2026-32255) :  ![starts](https://img.shields.io/github/stars/kOaDT/poc-cve-2026-32255.svg) ![forks](https://img.shields.io/github/forks/kOaDT/poc-cve-2026-32255.svg)

## CVE-2026-32247
 Graphiti is a framework for building and querying temporal context graphs for AI agents. Graphiti versions before 0.28.2 contained a Cypher injection vulnerability in shared search-filter construction for non-Kuzu backends. Attacker-controlled label values supplied through SearchFilters.node_labels were concatenated directly into Cypher label expressions without validation. In MCP deployments, this was exploitable not only through direct untrusted access to the Graphiti MCP server, but also through prompt injection against an LLM client that could be induced to call search_nodes with attacker-controlled entity_types values. The MCP server mapped entity_types to SearchFilters.node_labels, which then reached the vulnerable Cypher construction path. Affected backends included Neo4j, FalkorDB, and Neptune. Kuzu was not affected by the label-injection issue because it used parameterized label handling rather than string-interpolated Cypher labels. This issue was mitigated in 0.28.2.



- [https://github.com/romain-deperne/CVE-2026-32247](https://github.com/romain-deperne/CVE-2026-32247) :  ![starts](https://img.shields.io/github/stars/romain-deperne/CVE-2026-32247.svg) ![forks](https://img.shields.io/github/forks/romain-deperne/CVE-2026-32247.svg)

## CVE-2026-32238
 OpenEMR is a free and open source electronic health records and medical practice management application. Versions prior to 8.0.0.2 contain a Command injection vulnerability in the backup functionality that can be exploited by authenticated attackers. The vulnerability exists due to insufficient input validation in the backup functionality. Version 8.0.0.2 fixes the issue.



- [https://github.com/ChrisSub08/CVE-2026-32238_RemoteCodeExecutionOpenEMR8.0.0](https://github.com/ChrisSub08/CVE-2026-32238_RemoteCodeExecutionOpenEMR8.0.0) :  ![starts](https://img.shields.io/github/stars/ChrisSub08/CVE-2026-32238_RemoteCodeExecutionOpenEMR8.0.0.svg) ![forks](https://img.shields.io/github/forks/ChrisSub08/CVE-2026-32238_RemoteCodeExecutionOpenEMR8.0.0.svg)

## CVE-2026-32223
 Heap-based buffer overflow in Windows USB Print Driver allows an unauthorized attacker to elevate privileges with a physical attack.



- [https://github.com/enki-kr/CVE-2026-32223-USBPrint-Exploit](https://github.com/enki-kr/CVE-2026-32223-USBPrint-Exploit) :  ![starts](https://img.shields.io/github/stars/enki-kr/CVE-2026-32223-USBPrint-Exploit.svg) ![forks](https://img.shields.io/github/forks/enki-kr/CVE-2026-32223-USBPrint-Exploit.svg)

## CVE-2026-32202
 Protection mechanism failure in Windows Shell allows an unauthorized attacker to perform spoofing over a network.



- [https://github.com/virus-or-not/CVE-2026-32202](https://github.com/virus-or-not/CVE-2026-32202) :  ![starts](https://img.shields.io/github/stars/virus-or-not/CVE-2026-32202.svg) ![forks](https://img.shields.io/github/forks/virus-or-not/CVE-2026-32202.svg)

- [https://github.com/solarlynxsqueeze/CVE-2026-32202](https://github.com/solarlynxsqueeze/CVE-2026-32202) :  ![starts](https://img.shields.io/github/stars/solarlynxsqueeze/CVE-2026-32202.svg) ![forks](https://img.shields.io/github/forks/solarlynxsqueeze/CVE-2026-32202.svg)

## CVE-2026-32201
 Improper input validation in Microsoft Office SharePoint allows an unauthorized attacker to perform spoofing over a network.



- [https://github.com/B1tBit/CVE-2026-32201-exploit](https://github.com/B1tBit/CVE-2026-32201-exploit) :  ![starts](https://img.shields.io/github/stars/B1tBit/CVE-2026-32201-exploit.svg) ![forks](https://img.shields.io/github/forks/B1tBit/CVE-2026-32201-exploit.svg)

## CVE-2026-32136
 AdGuard Home is a network-wide software for blocking ads and tracking. Prior to 0.107.73, an unauthenticated remote attacker can bypass all authentication in AdGuardHome by sending an HTTP/1.1 request that requests an upgrade to HTTP/2 cleartext (h2c). Once the upgrade is accepted, the resulting HTTP/2 connection is handled by the inner mux, which has no authentication middleware attached. All subsequent HTTP/2 requests on that connection are processed as fully authenticated, regardless of whether any credentials were provided. This vulnerability is fixed in 0.107.73.



- [https://github.com/0xdak/CVE-2026-32136_exploit](https://github.com/0xdak/CVE-2026-32136_exploit) :  ![starts](https://img.shields.io/github/stars/0xdak/CVE-2026-32136_exploit.svg) ![forks](https://img.shields.io/github/forks/0xdak/CVE-2026-32136_exploit.svg)

## CVE-2026-32127
 OpenEMR is a free and open source electronic health records and medical practice management application. Prior to 8.0.0.1, OpenEMR contains a SQL injection vulnerability in the ajax graphs library that can be exploited by authenticated attackers. The vulnerability exists due to insufficient input validation in the ajax graphs library. This vulnerability is fixed in 8.0.0.1.



- [https://github.com/ChrisSub08/CVE-2026-32127_SqlInjectionVulnerabilityOpenEMR8.0.0](https://github.com/ChrisSub08/CVE-2026-32127_SqlInjectionVulnerabilityOpenEMR8.0.0) :  ![starts](https://img.shields.io/github/stars/ChrisSub08/CVE-2026-32127_SqlInjectionVulnerabilityOpenEMR8.0.0.svg) ![forks](https://img.shields.io/github/forks/ChrisSub08/CVE-2026-32127_SqlInjectionVulnerabilityOpenEMR8.0.0.svg)

## CVE-2026-32096
 Plunk is an open-source email platform built on top of AWS SES. Prior to 0.7.0, a Server-Side Request Forgery (SSRF) vulnerability existed in the SNS webhook handler. An unauthenticated attacker could send a crafted request that caused the server to make an arbitrary outbound HTTP GET request to any host accessible from the server. This vulnerability is fixed in 0.7.0.



- [https://github.com/andrebhu/CVE-2026-32096](https://github.com/andrebhu/CVE-2026-32096) :  ![starts](https://img.shields.io/github/stars/andrebhu/CVE-2026-32096.svg) ![forks](https://img.shields.io/github/forks/andrebhu/CVE-2026-32096.svg)

## CVE-2026-32015
 OpenClaw versions 2026.1.21 prior to 2026.2.19 contain a path hijacking vulnerability in tools.exec.safeBins that allows attackers to bypass allowlist checks by controlling process PATH resolution. Attackers who can influence the gateway process PATH or launch environment can execute trojan binaries with allowlisted names, such as jq, circumventing executable validation controls.



- [https://github.com/hargabyte/cve-scanner](https://github.com/hargabyte/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hargabyte/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hargabyte/cve-scanner.svg)

## CVE-2026-32013
 OpenClaw versions prior to 2026.2.25 contain a symlink traversal vulnerability in the agents.files.get and agents.files.set methods that allows reading and writing files outside the agent workspace. Attackers can exploit symlinked allowlisted files to access arbitrary host files within gateway process permissions, potentially enabling code execution through file overwrite attacks.



- [https://github.com/hargabyte/cve-scanner](https://github.com/hargabyte/cve-scanner) :  ![starts](https://img.shields.io/github/stars/hargabyte/cve-scanner.svg) ![forks](https://img.shields.io/github/forks/hargabyte/cve-scanner.svg)

## CVE-2026-31908
 Header injection vulnerability in Apache APISIX.

The attacker can take advantage of certain configuration in forward-auth plugin to inject malicious headers.
This issue affects Apache APISIX: from 2.12.0 through 3.15.0.

Users are recommended to upgrade to version 3.16.0, which fixes the issue.



- [https://github.com/MehranTurk/CVE-2026-31908](https://github.com/MehranTurk/CVE-2026-31908) :  ![starts](https://img.shields.io/github/stars/MehranTurk/CVE-2026-31908.svg) ![forks](https://img.shields.io/github/forks/MehranTurk/CVE-2026-31908.svg)

## CVE-2026-31900
 Black is the uncompromising Python code formatter. Black provides a GitHub action for formatting code. This action supports an option, use_pyproject: true, for reading the version of Black to use from the repository pyproject.toml. A malicious pull request could edit pyproject.toml to use a direct URL reference to a malicious repository. This could lead to arbitrary code execution in the context of the GitHub Action. Attackers could then gain access to secrets or permissions available in the context of the action. Version 26.3.0 fixes this vulnerability.



- [https://github.com/Batosay1337Lab/cve-2026-31900-lab](https://github.com/Batosay1337Lab/cve-2026-31900-lab) :  ![starts](https://img.shields.io/github/stars/Batosay1337Lab/cve-2026-31900-lab.svg) ![forks](https://img.shields.io/github/forks/Batosay1337Lab/cve-2026-31900-lab.svg)

## CVE-2026-31899
 CairoSVG is an SVG converter based on Cairo, a 2D graphics library. Prior to Kozea/CairoSVG has exponential denial of service via recursive use element amplification in cairosvg/defs.py. This causes CPU exhaustion from a small input.



- [https://github.com/SnailSploit/CVE-2026-31899](https://github.com/SnailSploit/CVE-2026-31899) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2026-31899.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2026-31899.svg)

## CVE-2026-31891
 Cockpit is a headless content management system. Any Cockpit CMS instance running version 2.13.4 or earlier with API access enabled is potentially affected by a a SQL Injection vulnerability in the MongoLite Aggregation Optimizer. Any deployment where the `/api/content/aggregate/{model}` endpoint is publicly accessible or reachable by untrusted users may be vulnerable, and attackers in possession of a valid read-only API key (the lowest privilege level) can exploit this vulnerability — no admin access is required. An attacker can inject arbitrary SQL via unsanitized field names in aggregation queries, bypass the `_state=1` published-content filter to access unpublished or restricted content, and extract unauthorized data from the underlying SQLite content database. This vulnerability has been patched in version 2.13.5. The fix applies the same field-name sanitization introduced in v2.13.3 for `toJsonPath()` to the `toJsonExtractRaw()` method in `lib/MongoLite/Aggregation/Optimizer.php`, closing the injection vector in the Aggregation Optimizer.



- [https://github.com/ffasterss/CVE-2026-31891](https://github.com/ffasterss/CVE-2026-31891) :  ![starts](https://img.shields.io/github/stars/ffasterss/CVE-2026-31891.svg) ![forks](https://img.shields.io/github/forks/ffasterss/CVE-2026-31891.svg)

## CVE-2026-31844
 An authenticated SQL Injection vulnerability (CWE-89) exists in the Koha staff interface in the /cgi-bin/koha/suggestion/suggestion.pl endpoint due to improper validation of the displayby parameter used by the GetDistinctValues functionality. A low-privileged staff user can inject arbitrary SQL queries via crafted requests to this parameter, allowing execution of unintended SQL statements and exposure of sensitive database information. Successful exploitation may lead to full compromise of the backend database, including disclosure or modification of stored data.



- [https://github.com/Mothra-1/CVE-2026-31844](https://github.com/Mothra-1/CVE-2026-31844) :  ![starts](https://img.shields.io/github/stars/Mothra-1/CVE-2026-31844.svg) ![forks](https://img.shields.io/github/forks/Mothra-1/CVE-2026-31844.svg)

## CVE-2026-31816
 Budibase is a low code platform for creating internal tools, workflows, and admin panels. In 3.31.4 and earlier, the Budibase server's authorized() middleware that protects every server-side API endpoint can be completely bypassed by appending a webhook path pattern to the query string of any request. The isWebhookEndpoint() function uses an unanchored regex that tests against ctx.request.url, which in Koa includes the full URL with query parameters. When the regex matches, the authorized() middleware immediately calls return next(), skipping all authentication, authorization, role checks, and CSRF protection. This means a completely unauthenticated, remote attacker can access any server-side API endpoint by simply appending ?/webhooks/trigger (or any webhook pattern variant) to the URL.



- [https://github.com/imjdl/CVE-2026-31816-rshell](https://github.com/imjdl/CVE-2026-31816-rshell) :  ![starts](https://img.shields.io/github/stars/imjdl/CVE-2026-31816-rshell.svg) ![forks](https://img.shields.io/github/forks/imjdl/CVE-2026-31816-rshell.svg)

## CVE-2026-31802
 node-tar is a full-featured Tar for Node.js. Prior to version 7.5.11, tar (npm) can be tricked into creating a symlink that points outside the extraction directory by using a drive-relative symlink target such as C:../../../target.txt, which enables file overwrite outside cwd during normal tar.x() extraction. This vulnerability is fixed in 7.5.11.



- [https://github.com/Jvr2022/CVE-2026-31802](https://github.com/Jvr2022/CVE-2026-31802) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-31802.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-31802.svg)

- [https://github.com/Recorded-texteditor120/CVE-2026-31802](https://github.com/Recorded-texteditor120/CVE-2026-31802) :  ![starts](https://img.shields.io/github/stars/Recorded-texteditor120/CVE-2026-31802.svg) ![forks](https://img.shields.io/github/forks/Recorded-texteditor120/CVE-2026-31802.svg)

## CVE-2026-31717
 In the Linux kernel, the following vulnerability has been resolved:

ksmbd: validate owner of durable handle on reconnect

Currently, ksmbd does not verify if the user attempting to reconnect
to a durable handle is the same user who originally opened the file.
This allows any authenticated user to hijack an orphaned durable handle
by predicting or brute-forcing the persistent ID.

According to MS-SMB2, the server MUST verify that the SecurityContext
of the reconnect request matches the SecurityContext associated with
the existing open.
Add a durable_owner structure to ksmbd_file to store the original opener's
UID, GID, and account name. and catpure the owner information when a file
handle becomes orphaned. and implementing ksmbd_vfs_compare_durable_owner()
to validate the identity of the requester during SMB2_CREATE (DHnC).



- [https://github.com/TurtleARM/CVE-2026-31717-KSMBD-Exploit](https://github.com/TurtleARM/CVE-2026-31717-KSMBD-Exploit) :  ![starts](https://img.shields.io/github/stars/TurtleARM/CVE-2026-31717-KSMBD-Exploit.svg) ![forks](https://img.shields.io/github/forks/TurtleARM/CVE-2026-31717-KSMBD-Exploit.svg)

## CVE-2026-31431
 In the Linux kernel, the following vulnerability has been resolved:

crypto: algif_aead - Revert to operating out-of-place

This mostly reverts commit 72548b093ee3 except for the copying of
the associated data.

There is no benefit in operating in-place in algif_aead since the
source and destination come from different mappings.  Get rid of
all the complexity added for in-place operation and just copy the
AD directly.



- [https://github.com/theori-io/copy-fail-CVE-2026-31431](https://github.com/theori-io/copy-fail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/theori-io/copy-fail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/theori-io/copy-fail-CVE-2026-31431.svg)

- [https://github.com/rootsecdev/cve_2026_31431](https://github.com/rootsecdev/cve_2026_31431) :  ![starts](https://img.shields.io/github/stars/rootsecdev/cve_2026_31431.svg) ![forks](https://img.shields.io/github/forks/rootsecdev/cve_2026_31431.svg)

- [https://github.com/tgies/copy-fail-c](https://github.com/tgies/copy-fail-c) :  ![starts](https://img.shields.io/github/stars/tgies/copy-fail-c.svg) ![forks](https://img.shields.io/github/forks/tgies/copy-fail-c.svg)

- [https://github.com/badsectorlabs/copyfail-go](https://github.com/badsectorlabs/copyfail-go) :  ![starts](https://img.shields.io/github/stars/badsectorlabs/copyfail-go.svg) ![forks](https://img.shields.io/github/forks/badsectorlabs/copyfail-go.svg)

- [https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC](https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC) :  ![starts](https://img.shields.io/github/stars/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC.svg) ![forks](https://img.shields.io/github/forks/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC.svg)

- [https://github.com/Sndav/CVE-2026-31431-Advanced-Exploit](https://github.com/Sndav/CVE-2026-31431-Advanced-Exploit) :  ![starts](https://img.shields.io/github/stars/Sndav/CVE-2026-31431-Advanced-Exploit.svg) ![forks](https://img.shields.io/github/forks/Sndav/CVE-2026-31431-Advanced-Exploit.svg)

- [https://github.com/painoob/Copy-Fail-Exploit-CVE-2026-31431](https://github.com/painoob/Copy-Fail-Exploit-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/painoob/Copy-Fail-Exploit-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/painoob/Copy-Fail-Exploit-CVE-2026-31431.svg)

- [https://github.com/adysec/cve-2026-31431](https://github.com/adysec/cve-2026-31431) :  ![starts](https://img.shields.io/github/stars/adysec/cve-2026-31431.svg) ![forks](https://img.shields.io/github/forks/adysec/cve-2026-31431.svg)

- [https://github.com/Crihexe/copy-fail-tiny-elf-CVE-2026-31431](https://github.com/Crihexe/copy-fail-tiny-elf-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Crihexe/copy-fail-tiny-elf-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Crihexe/copy-fail-tiny-elf-CVE-2026-31431.svg)

- [https://github.com/iss4cf0ng/CVE-2026-31431-Linux-Copy-Fail](https://github.com/iss4cf0ng/CVE-2026-31431-Linux-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/iss4cf0ng/CVE-2026-31431-Linux-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/iss4cf0ng/CVE-2026-31431-Linux-Copy-Fail.svg)

- [https://github.com/shadowabi/CVE-2026-31431-CopyFail-Universal-LPE](https://github.com/shadowabi/CVE-2026-31431-CopyFail-Universal-LPE) :  ![starts](https://img.shields.io/github/stars/shadowabi/CVE-2026-31431-CopyFail-Universal-LPE.svg) ![forks](https://img.shields.io/github/forks/shadowabi/CVE-2026-31431-CopyFail-Universal-LPE.svg)

- [https://github.com/sgkdev/page_inject](https://github.com/sgkdev/page_inject) :  ![starts](https://img.shields.io/github/stars/sgkdev/page_inject.svg) ![forks](https://img.shields.io/github/forks/sgkdev/page_inject.svg)

- [https://github.com/kadir/copy-fail-CVE-2026-31431-IOC](https://github.com/kadir/copy-fail-CVE-2026-31431-IOC) :  ![starts](https://img.shields.io/github/stars/kadir/copy-fail-CVE-2026-31431-IOC.svg) ![forks](https://img.shields.io/github/forks/kadir/copy-fail-CVE-2026-31431-IOC.svg)

- [https://github.com/0xShe/CVE-2026-31431](https://github.com/0xShe/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/0xShe/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/0xShe/CVE-2026-31431.svg)

- [https://github.com/cozystack/copy-fail-blocker](https://github.com/cozystack/copy-fail-blocker) :  ![starts](https://img.shields.io/github/stars/cozystack/copy-fail-blocker.svg) ![forks](https://img.shields.io/github/forks/cozystack/copy-fail-blocker.svg)

- [https://github.com/wgnet/wg.copyfail.patch](https://github.com/wgnet/wg.copyfail.patch) :  ![starts](https://img.shields.io/github/stars/wgnet/wg.copyfail.patch.svg) ![forks](https://img.shields.io/github/forks/wgnet/wg.copyfail.patch.svg)

- [https://github.com/jbnetwork-git/copy-fail-check](https://github.com/jbnetwork-git/copy-fail-check) :  ![starts](https://img.shields.io/github/stars/jbnetwork-git/copy-fail-check.svg) ![forks](https://img.shields.io/github/forks/jbnetwork-git/copy-fail-check.svg)

- [https://github.com/liamromanis101/CVE-2026-31431-Copy-Fail---Vulnerability-Detection-Script](https://github.com/liamromanis101/CVE-2026-31431-Copy-Fail---Vulnerability-Detection-Script) :  ![starts](https://img.shields.io/github/stars/liamromanis101/CVE-2026-31431-Copy-Fail---Vulnerability-Detection-Script.svg) ![forks](https://img.shields.io/github/forks/liamromanis101/CVE-2026-31431-Copy-Fail---Vulnerability-Detection-Script.svg)

- [https://github.com/diemoeve/copyfail-rs](https://github.com/diemoeve/copyfail-rs) :  ![starts](https://img.shields.io/github/stars/diemoeve/copyfail-rs.svg) ![forks](https://img.shields.io/github/forks/diemoeve/copyfail-rs.svg)

- [https://github.com/ZephrFish/CopyFail-CVE-2026-31431](https://github.com/ZephrFish/CopyFail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/ZephrFish/CopyFail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/ZephrFish/CopyFail-CVE-2026-31431.svg)

- [https://github.com/qi4L/CVE-2026-31431-Container-Escape](https://github.com/qi4L/CVE-2026-31431-Container-Escape) :  ![starts](https://img.shields.io/github/stars/qi4L/CVE-2026-31431-Container-Escape.svg) ![forks](https://img.shields.io/github/forks/qi4L/CVE-2026-31431-Container-Escape.svg)

- [https://github.com/philfry/cve-2026-31431-ftrace](https://github.com/philfry/cve-2026-31431-ftrace) :  ![starts](https://img.shields.io/github/stars/philfry/cve-2026-31431-ftrace.svg) ![forks](https://img.shields.io/github/forks/philfry/cve-2026-31431-ftrace.svg)

- [https://github.com/sammwyy/copyfail-rs](https://github.com/sammwyy/copyfail-rs) :  ![starts](https://img.shields.io/github/stars/sammwyy/copyfail-rs.svg) ![forks](https://img.shields.io/github/forks/sammwyy/copyfail-rs.svg)

- [https://github.com/MartinPham/copy-fail-CVE-2026-31431-php](https://github.com/MartinPham/copy-fail-CVE-2026-31431-php) :  ![starts](https://img.shields.io/github/stars/MartinPham/copy-fail-CVE-2026-31431-php.svg) ![forks](https://img.shields.io/github/forks/MartinPham/copy-fail-CVE-2026-31431-php.svg)

- [https://github.com/ochebotar/copy-fail-CVE-2026-31431-detection-probe](https://github.com/ochebotar/copy-fail-CVE-2026-31431-detection-probe) :  ![starts](https://img.shields.io/github/stars/ochebotar/copy-fail-CVE-2026-31431-detection-probe.svg) ![forks](https://img.shields.io/github/forks/ochebotar/copy-fail-CVE-2026-31431-detection-probe.svg)

- [https://github.com/rfxn/copyfail](https://github.com/rfxn/copyfail) :  ![starts](https://img.shields.io/github/stars/rfxn/copyfail.svg) ![forks](https://img.shields.io/github/forks/rfxn/copyfail.svg)

- [https://github.com/atgreen/block-copyfail](https://github.com/atgreen/block-copyfail) :  ![starts](https://img.shields.io/github/stars/atgreen/block-copyfail.svg) ![forks](https://img.shields.io/github/forks/atgreen/block-copyfail.svg)

- [https://github.com/desultory/CVE-2026-31431](https://github.com/desultory/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/desultory/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/desultory/CVE-2026-31431.svg)

- [https://github.com/yandex-cloud-examples/yc-mk8s-copy-fail-mitigation](https://github.com/yandex-cloud-examples/yc-mk8s-copy-fail-mitigation) :  ![starts](https://img.shields.io/github/stars/yandex-cloud-examples/yc-mk8s-copy-fail-mitigation.svg) ![forks](https://img.shields.io/github/forks/yandex-cloud-examples/yc-mk8s-copy-fail-mitigation.svg)

- [https://github.com/SeanRickerd/cve-2026-31431](https://github.com/SeanRickerd/cve-2026-31431) :  ![starts](https://img.shields.io/github/stars/SeanRickerd/cve-2026-31431.svg) ![forks](https://img.shields.io/github/forks/SeanRickerd/cve-2026-31431.svg)

- [https://github.com/malwarekid/CVE-2026-31431](https://github.com/malwarekid/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/malwarekid/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/malwarekid/CVE-2026-31431.svg)

- [https://github.com/JuanBindez/CVE-2026-31431](https://github.com/JuanBindez/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/JuanBindez/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/JuanBindez/CVE-2026-31431.svg)

- [https://github.com/Dabbleam/CVE-2026-31431-mitigation](https://github.com/Dabbleam/CVE-2026-31431-mitigation) :  ![starts](https://img.shields.io/github/stars/Dabbleam/CVE-2026-31431-mitigation.svg) ![forks](https://img.shields.io/github/forks/Dabbleam/CVE-2026-31431-mitigation.svg)

- [https://github.com/ErdemOzgen/copy-fail-cve-2026-31431](https://github.com/ErdemOzgen/copy-fail-cve-2026-31431) :  ![starts](https://img.shields.io/github/stars/ErdemOzgen/copy-fail-cve-2026-31431.svg) ![forks](https://img.shields.io/github/forks/ErdemOzgen/copy-fail-cve-2026-31431.svg)

- [https://github.com/Smarttfoxx/copyfail](https://github.com/Smarttfoxx/copyfail) :  ![starts](https://img.shields.io/github/stars/Smarttfoxx/copyfail.svg) ![forks](https://img.shields.io/github/forks/Smarttfoxx/copyfail.svg)

- [https://github.com/Shotafry/CopyFail-Exploits-CVE-2026-31431](https://github.com/Shotafry/CopyFail-Exploits-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Shotafry/CopyFail-Exploits-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Shotafry/CopyFail-Exploits-CVE-2026-31431.svg)

- [https://github.com/AliHzSec/CVE-2026-31431](https://github.com/AliHzSec/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/AliHzSec/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/AliHzSec/CVE-2026-31431.svg)

- [https://github.com/b5null/CVE-2026-31431-C](https://github.com/b5null/CVE-2026-31431-C) :  ![starts](https://img.shields.io/github/stars/b5null/CVE-2026-31431-C.svg) ![forks](https://img.shields.io/github/forks/b5null/CVE-2026-31431-C.svg)

- [https://github.com/wesmar/CVE-2026-31431](https://github.com/wesmar/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/wesmar/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/wesmar/CVE-2026-31431.svg)

- [https://github.com/Xerxes-2/CVE-2026-31431-rs](https://github.com/Xerxes-2/CVE-2026-31431-rs) :  ![starts](https://img.shields.io/github/stars/Xerxes-2/CVE-2026-31431-rs.svg) ![forks](https://img.shields.io/github/forks/Xerxes-2/CVE-2026-31431-rs.svg)

- [https://github.com/wuwu001/CVE-2026-31431-exploit](https://github.com/wuwu001/CVE-2026-31431-exploit) :  ![starts](https://img.shields.io/github/stars/wuwu001/CVE-2026-31431-exploit.svg) ![forks](https://img.shields.io/github/forks/wuwu001/CVE-2026-31431-exploit.svg)

- [https://github.com/mahdi13830510/CVE-2026-31431-mitigation-suite](https://github.com/mahdi13830510/CVE-2026-31431-mitigation-suite) :  ![starts](https://img.shields.io/github/stars/mahdi13830510/CVE-2026-31431-mitigation-suite.svg) ![forks](https://img.shields.io/github/forks/mahdi13830510/CVE-2026-31431-mitigation-suite.svg)

- [https://github.com/bigwario/copy-fail-CVE-2026-31431-C](https://github.com/bigwario/copy-fail-CVE-2026-31431-C) :  ![starts](https://img.shields.io/github/stars/bigwario/copy-fail-CVE-2026-31431-C.svg) ![forks](https://img.shields.io/github/forks/bigwario/copy-fail-CVE-2026-31431-C.svg)

- [https://github.com/beatbeast007/Linux-CopyFail-C-Version-CVE-2026-31431](https://github.com/beatbeast007/Linux-CopyFail-C-Version-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/beatbeast007/Linux-CopyFail-C-Version-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/beatbeast007/Linux-CopyFail-C-Version-CVE-2026-31431.svg)

- [https://github.com/infiniroot/ansible-mitigate-copyfail-dirtyfrag](https://github.com/infiniroot/ansible-mitigate-copyfail-dirtyfrag) :  ![starts](https://img.shields.io/github/stars/infiniroot/ansible-mitigate-copyfail-dirtyfrag.svg) ![forks](https://img.shields.io/github/forks/infiniroot/ansible-mitigate-copyfail-dirtyfrag.svg)

- [https://github.com/xeloxa/copyfail-exploit](https://github.com/xeloxa/copyfail-exploit) :  ![starts](https://img.shields.io/github/stars/xeloxa/copyfail-exploit.svg) ![forks](https://img.shields.io/github/forks/xeloxa/copyfail-exploit.svg)

- [https://github.com/Boos4721/copyfail-rs](https://github.com/Boos4721/copyfail-rs) :  ![starts](https://img.shields.io/github/stars/Boos4721/copyfail-rs.svg) ![forks](https://img.shields.io/github/forks/Boos4721/copyfail-rs.svg)

- [https://github.com/XsanFlip/CVE-2026-31431-Patch](https://github.com/XsanFlip/CVE-2026-31431-Patch) :  ![starts](https://img.shields.io/github/stars/XsanFlip/CVE-2026-31431-Patch.svg) ![forks](https://img.shields.io/github/forks/XsanFlip/CVE-2026-31431-Patch.svg)

- [https://github.com/AdityaBhatt3010/CVE-2026-31431](https://github.com/AdityaBhatt3010/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2026-31431.svg)

- [https://github.com/povzayd/CVE-2026-31431](https://github.com/povzayd/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/povzayd/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/povzayd/CVE-2026-31431.svg)

- [https://github.com/aestechno/cve-2026-31431-ansible](https://github.com/aestechno/cve-2026-31431-ansible) :  ![starts](https://img.shields.io/github/stars/aestechno/cve-2026-31431-ansible.svg) ![forks](https://img.shields.io/github/forks/aestechno/cve-2026-31431-ansible.svg)

- [https://github.com/Sl4cK0TH/CVE-2026-31431-PoC](https://github.com/Sl4cK0TH/CVE-2026-31431-PoC) :  ![starts](https://img.shields.io/github/stars/Sl4cK0TH/CVE-2026-31431-PoC.svg) ![forks](https://img.shields.io/github/forks/Sl4cK0TH/CVE-2026-31431-PoC.svg)

- [https://github.com/M4xSec/CVE-2026-31431-RCE-Exploit](https://github.com/M4xSec/CVE-2026-31431-RCE-Exploit) :  ![starts](https://img.shields.io/github/stars/M4xSec/CVE-2026-31431-RCE-Exploit.svg) ![forks](https://img.shields.io/github/forks/M4xSec/CVE-2026-31431-RCE-Exploit.svg)

- [https://github.com/KaraZajac/DIRTYFAIL](https://github.com/KaraZajac/DIRTYFAIL) :  ![starts](https://img.shields.io/github/stars/KaraZajac/DIRTYFAIL.svg) ![forks](https://img.shields.io/github/forks/KaraZajac/DIRTYFAIL.svg)

- [https://github.com/toxy4ny/copy-fail-exploit-on-c-redteam](https://github.com/toxy4ny/copy-fail-exploit-on-c-redteam) :  ![starts](https://img.shields.io/github/stars/toxy4ny/copy-fail-exploit-on-c-redteam.svg) ![forks](https://img.shields.io/github/forks/toxy4ny/copy-fail-exploit-on-c-redteam.svg)

- [https://github.com/mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4](https://github.com/mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4) :  ![starts](https://img.shields.io/github/stars/mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4.svg) ![forks](https://img.shields.io/github/forks/mym0us3r/COPY-FAIL-Detection-with-Wazuh-4.14.4.svg)

- [https://github.com/SpenserCai/copy_fail](https://github.com/SpenserCai/copy_fail) :  ![starts](https://img.shields.io/github/stars/SpenserCai/copy_fail.svg) ![forks](https://img.shields.io/github/forks/SpenserCai/copy_fail.svg)

- [https://github.com/0xBlackash/CVE-2026-31431](https://github.com/0xBlackash/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-31431.svg)

- [https://github.com/ExploitEoom/CVE-2026-31431](https://github.com/ExploitEoom/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/ExploitEoom/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/ExploitEoom/CVE-2026-31431.svg)

- [https://github.com/rvizx/CVE-2026-31431](https://github.com/rvizx/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/rvizx/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/rvizx/CVE-2026-31431.svg)

- [https://github.com/Webhosting4U/Copy-Fail_Detect_and_mitigate_CVE-2026-31431](https://github.com/Webhosting4U/Copy-Fail_Detect_and_mitigate_CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Webhosting4U/Copy-Fail_Detect_and_mitigate_CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Webhosting4U/Copy-Fail_Detect_and_mitigate_CVE-2026-31431.svg)

- [https://github.com/lonelyor/CVE-2026-31431-exp](https://github.com/lonelyor/CVE-2026-31431-exp) :  ![starts](https://img.shields.io/github/stars/lonelyor/CVE-2026-31431-exp.svg) ![forks](https://img.shields.io/github/forks/lonelyor/CVE-2026-31431-exp.svg)

- [https://github.com/ben-slates/CVE-2026-31431-Exploit](https://github.com/ben-slates/CVE-2026-31431-Exploit) :  ![starts](https://img.shields.io/github/stars/ben-slates/CVE-2026-31431-Exploit.svg) ![forks](https://img.shields.io/github/forks/ben-slates/CVE-2026-31431-Exploit.svg)

- [https://github.com/darioomatos/cve-2026-31431-copyfail](https://github.com/darioomatos/cve-2026-31431-copyfail) :  ![starts](https://img.shields.io/github/stars/darioomatos/cve-2026-31431-copyfail.svg) ![forks](https://img.shields.io/github/forks/darioomatos/cve-2026-31431-copyfail.svg)

- [https://github.com/sec17br/CVE-2026-31431-Copy-Fail](https://github.com/sec17br/CVE-2026-31431-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/sec17br/CVE-2026-31431-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/sec17br/CVE-2026-31431-Copy-Fail.svg)

- [https://github.com/cyber-joker/copy-fail-python](https://github.com/cyber-joker/copy-fail-python) :  ![starts](https://img.shields.io/github/stars/cyber-joker/copy-fail-python.svg) ![forks](https://img.shields.io/github/forks/cyber-joker/copy-fail-python.svg)

- [https://github.com/KanbaraAkihito/CVE-2026-31431-copyfail-rs](https://github.com/KanbaraAkihito/CVE-2026-31431-copyfail-rs) :  ![starts](https://img.shields.io/github/stars/KanbaraAkihito/CVE-2026-31431-copyfail-rs.svg) ![forks](https://img.shields.io/github/forks/KanbaraAkihito/CVE-2026-31431-copyfail-rs.svg)

- [https://github.com/wvverez/CVE-2026-31431-Copy-Fail](https://github.com/wvverez/CVE-2026-31431-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/wvverez/CVE-2026-31431-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/wvverez/CVE-2026-31431-Copy-Fail.svg)

- [https://github.com/scriptzteam/Paranoid-Copy-Fail-CVE-2026-31431](https://github.com/scriptzteam/Paranoid-Copy-Fail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/scriptzteam/Paranoid-Copy-Fail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/scriptzteam/Paranoid-Copy-Fail-CVE-2026-31431.svg)

- [https://github.com/bootsareme/copyfail-deconstructed](https://github.com/bootsareme/copyfail-deconstructed) :  ![starts](https://img.shields.io/github/stars/bootsareme/copyfail-deconstructed.svg) ![forks](https://img.shields.io/github/forks/bootsareme/copyfail-deconstructed.svg)

- [https://github.com/kvakirsanov/CVE-2026-31431-live-process-code-injection](https://github.com/kvakirsanov/CVE-2026-31431-live-process-code-injection) :  ![starts](https://img.shields.io/github/stars/kvakirsanov/CVE-2026-31431-live-process-code-injection.svg) ![forks](https://img.shields.io/github/forks/kvakirsanov/CVE-2026-31431-live-process-code-injection.svg)

- [https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Statically-PoC](https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Statically-PoC) :  ![starts](https://img.shields.io/github/stars/Percivalll/Copy-Fail-CVE-2026-31431-Statically-PoC.svg) ![forks](https://img.shields.io/github/forks/Percivalll/Copy-Fail-CVE-2026-31431-Statically-PoC.svg)

- [https://github.com/Huchangzhi/autorootlinux](https://github.com/Huchangzhi/autorootlinux) :  ![starts](https://img.shields.io/github/stars/Huchangzhi/autorootlinux.svg) ![forks](https://img.shields.io/github/forks/Huchangzhi/autorootlinux.svg)

- [https://github.com/parmstro/cfDr](https://github.com/parmstro/cfDr) :  ![starts](https://img.shields.io/github/stars/parmstro/cfDr.svg) ![forks](https://img.shields.io/github/forks/parmstro/cfDr.svg)

- [https://github.com/juliosuas/copyfail-guard](https://github.com/juliosuas/copyfail-guard) :  ![starts](https://img.shields.io/github/stars/juliosuas/copyfail-guard.svg) ![forks](https://img.shields.io/github/forks/juliosuas/copyfail-guard.svg)

- [https://github.com/krisiasty/vcheck](https://github.com/krisiasty/vcheck) :  ![starts](https://img.shields.io/github/stars/krisiasty/vcheck.svg) ![forks](https://img.shields.io/github/forks/krisiasty/vcheck.svg)

- [https://github.com/codesource/copyfail-check](https://github.com/codesource/copyfail-check) :  ![starts](https://img.shields.io/github/stars/codesource/copyfail-check.svg) ![forks](https://img.shields.io/github/forks/codesource/copyfail-check.svg)

- [https://github.com/mahradbt/copyfail-mitigation](https://github.com/mahradbt/copyfail-mitigation) :  ![starts](https://img.shields.io/github/stars/mahradbt/copyfail-mitigation.svg) ![forks](https://img.shields.io/github/forks/mahradbt/copyfail-mitigation.svg)

- [https://github.com/0xlane/pagecache-guard](https://github.com/0xlane/pagecache-guard) :  ![starts](https://img.shields.io/github/stars/0xlane/pagecache-guard.svg) ![forks](https://img.shields.io/github/forks/0xlane/pagecache-guard.svg)

- [https://github.com/mrunalp/block-copyfail](https://github.com/mrunalp/block-copyfail) :  ![starts](https://img.shields.io/github/stars/mrunalp/block-copyfail.svg) ![forks](https://img.shields.io/github/forks/mrunalp/block-copyfail.svg)

- [https://github.com/yxdm02/CVE-2026-31431](https://github.com/yxdm02/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/yxdm02/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/yxdm02/CVE-2026-31431.svg)

- [https://github.com/pedromizz/copy-fail](https://github.com/pedromizz/copy-fail) :  ![starts](https://img.shields.io/github/stars/pedromizz/copy-fail.svg) ![forks](https://img.shields.io/github/forks/pedromizz/copy-fail.svg)

- [https://github.com/gagaltotal/cve-2026-31431-copy-fail](https://github.com/gagaltotal/cve-2026-31431-copy-fail) :  ![starts](https://img.shields.io/github/stars/gagaltotal/cve-2026-31431-copy-fail.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/cve-2026-31431-copy-fail.svg)

- [https://github.com/poyea/CVE-2026-31431.c](https://github.com/poyea/CVE-2026-31431.c) :  ![starts](https://img.shields.io/github/stars/poyea/CVE-2026-31431.c.svg) ![forks](https://img.shields.io/github/forks/poyea/CVE-2026-31431.c.svg)

- [https://github.com/Alfredooe/CVE-2026-31431](https://github.com/Alfredooe/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Alfredooe/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Alfredooe/CVE-2026-31431.svg)

- [https://github.com/nisec-eric/cve-2026-31431](https://github.com/nisec-eric/cve-2026-31431) :  ![starts](https://img.shields.io/github/stars/nisec-eric/cve-2026-31431.svg) ![forks](https://img.shields.io/github/forks/nisec-eric/cve-2026-31431.svg)

- [https://github.com/pascal-gujer/CVE-2026-31431](https://github.com/pascal-gujer/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/pascal-gujer/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/pascal-gujer/CVE-2026-31431.svg)

- [https://github.com/mfloresdacunha/CVE-2026-31431](https://github.com/mfloresdacunha/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/mfloresdacunha/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/mfloresdacunha/CVE-2026-31431.svg)

- [https://github.com/mishl-dev/CVE_2026_31431](https://github.com/mishl-dev/CVE_2026_31431) :  ![starts](https://img.shields.io/github/stars/mishl-dev/CVE_2026_31431.svg) ![forks](https://img.shields.io/github/forks/mishl-dev/CVE_2026_31431.svg)

- [https://github.com/TheMalwareGuardian/CVE-2026-31431](https://github.com/TheMalwareGuardian/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2026-31431.svg)

- [https://github.com/slauger/CVE-2026-31431](https://github.com/slauger/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/slauger/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/slauger/CVE-2026-31431.svg)

- [https://github.com/yiyihuohuo/CVE-2026-31431](https://github.com/yiyihuohuo/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/yiyihuohuo/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/yiyihuohuo/CVE-2026-31431.svg)

- [https://github.com/Gr-1m/CVE-2026-31431](https://github.com/Gr-1m/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Gr-1m/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Gr-1m/CVE-2026-31431.svg)

- [https://github.com/haydenjames/CVE-2026-31431-check](https://github.com/haydenjames/CVE-2026-31431-check) :  ![starts](https://img.shields.io/github/stars/haydenjames/CVE-2026-31431-check.svg) ![forks](https://img.shields.io/github/forks/haydenjames/CVE-2026-31431-check.svg)

- [https://github.com/galoryber/CVE-2026-31431-cleaned](https://github.com/galoryber/CVE-2026-31431-cleaned) :  ![starts](https://img.shields.io/github/stars/galoryber/CVE-2026-31431-cleaned.svg) ![forks](https://img.shields.io/github/forks/galoryber/CVE-2026-31431-cleaned.svg)

- [https://github.com/amdisrar/cve-2026-31431-mitigation](https://github.com/amdisrar/cve-2026-31431-mitigation) :  ![starts](https://img.shields.io/github/stars/amdisrar/cve-2026-31431-mitigation.svg) ![forks](https://img.shields.io/github/forks/amdisrar/cve-2026-31431-mitigation.svg)

- [https://github.com/alvaroguzmancode/CVE-2026-31431-mitigacion](https://github.com/alvaroguzmancode/CVE-2026-31431-mitigacion) :  ![starts](https://img.shields.io/github/stars/alvaroguzmancode/CVE-2026-31431-mitigacion.svg) ![forks](https://img.shields.io/github/forks/alvaroguzmancode/CVE-2026-31431-mitigacion.svg)

- [https://github.com/Trex1e/copyfail-CVE-2026-31431](https://github.com/Trex1e/copyfail-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/Trex1e/copyfail-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/Trex1e/copyfail-CVE-2026-31431.svg)

- [https://github.com/insomnisec/Detections-CVE-2026-31431](https://github.com/insomnisec/Detections-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/insomnisec/Detections-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/insomnisec/Detections-CVE-2026-31431.svg)

- [https://github.com/yuspring/cve-2026-31431-poc](https://github.com/yuspring/cve-2026-31431-poc) :  ![starts](https://img.shields.io/github/stars/yuspring/cve-2026-31431-poc.svg) ![forks](https://img.shields.io/github/forks/yuspring/cve-2026-31431-poc.svg)

## CVE-2026-31429
 In the Linux kernel, the following vulnerability has been resolved:

net: skb: fix cross-cache free of KFENCE-allocated skb head

SKB_SMALL_HEAD_CACHE_SIZE is intentionally set to a non-power-of-2
value (e.g. 704 on x86_64) to avoid collisions with generic kmalloc
bucket sizes. This ensures that skb_kfree_head() can reliably use
skb_end_offset to distinguish skb heads allocated from
skb_small_head_cache vs. generic kmalloc caches.

However, when KFENCE is enabled, kfence_ksize() returns the exact
requested allocation size instead of the slab bucket size. If a caller
(e.g. bpf_test_init) allocates skb head data via kzalloc() and the
requested size happens to equal SKB_SMALL_HEAD_CACHE_SIZE, then
slab_build_skb() - ksize() returns that exact value. After subtracting
skb_shared_info overhead, skb_end_offset ends up matching
SKB_SMALL_HEAD_HEADROOM, causing skb_kfree_head() to incorrectly free
the object to skb_small_head_cache instead of back to the original
kmalloc cache, resulting in a slab cross-cache free:

  kmem_cache_free(skbuff_small_head): Wrong slab cache. Expected
  skbuff_small_head but got kmalloc-1k

Fix this by always calling kfree(head) in skb_kfree_head(). This keeps
the free path generic and avoids allocator-specific misclassification
for KFENCE objects.



- [https://github.com/bluedragonsecurity/CVE-2026-31429-POC](https://github.com/bluedragonsecurity/CVE-2026-31429-POC) :  ![starts](https://img.shields.io/github/stars/bluedragonsecurity/CVE-2026-31429-POC.svg) ![forks](https://img.shields.io/github/forks/bluedragonsecurity/CVE-2026-31429-POC.svg)

## CVE-2026-31413
 In the Linux kernel, the following vulnerability has been resolved:

bpf: Fix unsound scalar forking in maybe_fork_scalars() for BPF_OR

maybe_fork_scalars() is called for both BPF_AND and BPF_OR when the
source operand is a constant.  When dst has signed range [-1, 0], it
forks the verifier state: the pushed path gets dst = 0, the current
path gets dst = -1.

For BPF_AND this is correct: 0 & K == 0.
For BPF_OR this is wrong:    0 | K == K, not 0.

The pushed path therefore tracks dst as 0 when the runtime value is K,
producing an exploitable verifier/runtime divergence that allows
out-of-bounds map access.

Fix this by passing env-insn_idx (instead of env-insn_idx + 1) to
push_stack(), so the pushed path re-executes the ALU instruction with
dst = 0 and naturally computes the correct result for any opcode.



- [https://github.com/Rat5ak/CVE-2026-31413-BPF-Container-Escape](https://github.com/Rat5ak/CVE-2026-31413-BPF-Container-Escape) :  ![starts](https://img.shields.io/github/stars/Rat5ak/CVE-2026-31413-BPF-Container-Escape.svg) ![forks](https://img.shields.io/github/forks/Rat5ak/CVE-2026-31413-BPF-Container-Escape.svg)

## CVE-2026-31402
 In the Linux kernel, the following vulnerability has been resolved:

nfsd: fix heap overflow in NFSv4.0 LOCK replay cache

The NFSv4.0 replay cache uses a fixed 112-byte inline buffer
(rp_ibuf[NFSD4_REPLAY_ISIZE]) to store encoded operation responses.
This size was calculated based on OPEN responses and does not account
for LOCK denied responses, which include the conflicting lock owner as
a variable-length field up to 1024 bytes (NFS4_OPAQUE_LIMIT).

When a LOCK operation is denied due to a conflict with an existing lock
that has a large owner, nfsd4_encode_operation() copies the full encoded
response into the undersized replay buffer via read_bytes_from_xdr_buf()
with no bounds check. This results in a slab-out-of-bounds write of up
to 944 bytes past the end of the buffer, corrupting adjacent heap memory.

This can be triggered remotely by an unauthenticated attacker with two
cooperating NFSv4.0 clients: one sets a lock with a large owner string,
then the other requests a conflicting lock to provoke the denial.

We could fix this by increasing NFSD4_REPLAY_ISIZE to allow for a full
opaque, but that would increase the size of every stateowner, when most
lockowners are not that large.

Instead, fix this by checking the encoded response length against
NFSD4_REPLAY_ISIZE before copying into the replay buffer. If the
response is too large, set rp_buflen to 0 to skip caching the replay
payload. The status is still cached, and the client already received the
correct response on the original request.



- [https://github.com/0xBlackash/CVE-2026-31402](https://github.com/0xBlackash/CVE-2026-31402) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-31402.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-31402.svg)

## CVE-2026-31283
 In Totara LMS v19.1.5 and before, the forgot password API does not implement rate limiting for the target email address. which can be used for an Email Bombing attack. NOTE: the Supplier's position is that the pwresettime configuration defaults to 30 minutes, the pwresettime configuration is a hard control enforced via flag PWRESET_STATUS_ALREADYSENT, and no further password-reset email messages are sent if this flag is active for a specific email address.



- [https://github.com/saykino/CVE-2026-31283](https://github.com/saykino/CVE-2026-31283) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2026-31283.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2026-31283.svg)

## CVE-2026-31282
 Totara LMS v19.1.5 and before is vulnerable to Incorrect Access Control. The login page code can be manipulated to reveal the login form. An attacker can chain that with missing rate-limit on the login form to launch a brute force attack. NOTE: this is disputed by the Supplier because (1) local login is enabled/disabled server side (this is not a client side control); (2) there is no evidence SSO login can be bypassed to allow local login; and (3) there is no evidence that local login can be performed when disabled server side.



- [https://github.com/saykino/CVE-2026-31282](https://github.com/saykino/CVE-2026-31282) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2026-31282.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2026-31282.svg)

## CVE-2026-31281
 Totara LMS v19.1.5 and before is vulnerable to HTML Injection. An attacker can inject malicious HTML code in a message and send it to all the users in the application, resulting in executing the code and may lead to session hijacking and executing commands on the victim's browser. NOTE: The supplier states that the product name is Totara Learning and that the functionality referenced is the in app messaging client. They note that the in app messaging client only has the ability to embed a specific allowed list of HTML tags commonly used for text enhancement, which includes italic, bold, underline, strong, etc. Last, they state that the in app messaging client cannot embed script, style, iframe, object, embed, form, input, button, svg, math, etc., and any attempt to embed tags or attributes outside of the allowed list (including onerror, onaction, etc.) is sanitized via DOMPurify.



- [https://github.com/saykino/CVE-2026-31281](https://github.com/saykino/CVE-2026-31281) :  ![starts](https://img.shields.io/github/stars/saykino/CVE-2026-31281.svg) ![forks](https://img.shields.io/github/forks/saykino/CVE-2026-31281.svg)

## CVE-2026-31280
 An issue in the Bluetooth RFCOMM service of Parani M10 Motorcycle Intercom v2.1.3 allows unauthorized attackers to cause a Denial of Service (DoS) via supplying crafted RFCOMM frames.



- [https://github.com/CipherX1802/CVE-2026-31280-Insecure-Bluetooth-RFCOMM-Leading-to-Device-Crash-in-Parani-M10-Intercom](https://github.com/CipherX1802/CVE-2026-31280-Insecure-Bluetooth-RFCOMM-Leading-to-Device-Crash-in-Parani-M10-Intercom) :  ![starts](https://img.shields.io/github/stars/CipherX1802/CVE-2026-31280-Insecure-Bluetooth-RFCOMM-Leading-to-Device-Crash-in-Parani-M10-Intercom.svg) ![forks](https://img.shields.io/github/forks/CipherX1802/CVE-2026-31280-Insecure-Bluetooth-RFCOMM-Leading-to-Device-Crash-in-Parani-M10-Intercom.svg)

## CVE-2026-31048
 An issue in the codepickle/code protocol of Pyro v3.x allows attackers to execute arbitrary code via supplying a crafted pickled string message.



- [https://github.com/Sif-0x01/security-advisories](https://github.com/Sif-0x01/security-advisories) :  ![starts](https://img.shields.io/github/stars/Sif-0x01/security-advisories.svg) ![forks](https://img.shields.io/github/forks/Sif-0x01/security-advisories.svg)

## CVE-2026-30952
 liquidjs is a Shopify / GitHub Pages compatible template engine in pure JavaScript. Prior to 10.25.0, the layout, render, and include tags allow arbitrary file access via absolute paths (either as string literals or through Liquid variables, the latter require dynamicPartials: true, which is the default). This poses a security risk when malicious users are allowed to control the template content or specify the filepath to be included as a Liquid variable. This vulnerability is fixed in 10.25.0.



- [https://github.com/MorielHarush/CVE-2026-30952-PoC](https://github.com/MorielHarush/CVE-2026-30952-PoC) :  ![starts](https://img.shields.io/github/stars/MorielHarush/CVE-2026-30952-PoC.svg) ![forks](https://img.shields.io/github/forks/MorielHarush/CVE-2026-30952-PoC.svg)

## CVE-2026-30951
 Sequelize is a Node.js ORM tool. Prior to 6.37.8, there is SQL injection via unescaped cast type in JSON/JSONB where clause processing. The _traverseJSON() function splits JSON path keys on :: to extract a cast type, which is interpolated raw into CAST(... AS type) SQL. An attacker who controls JSON object keys can inject arbitrary SQL and exfiltrate data from any table. This vulnerability is fixed in 6.37.8.



- [https://github.com/EQSTLab/CVE-2026-30951](https://github.com/EQSTLab/CVE-2026-30951) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-30951.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-30951.svg)

## CVE-2026-30945
 StudioCMS is a server-side-rendered, Astro native, headless content management system. Prior to 0.4.0, the DELETE /studiocms_api/dashboard/api-tokens endpoint allows any authenticated user with editor privileges or above to revoke API tokens belonging to any other user, including admin and owner accounts. The handler accepts tokenID and userID directly from the request payload without verifying token ownership, caller identity, or role hierarchy. This enables targeted denial of service against critical integrations and automations. This vulnerability is fixed in 0.4.0.



- [https://github.com/FilipeGaudard/CVE-2026-30945-PoC](https://github.com/FilipeGaudard/CVE-2026-30945-PoC) :  ![starts](https://img.shields.io/github/stars/FilipeGaudard/CVE-2026-30945-PoC.svg) ![forks](https://img.shields.io/github/forks/FilipeGaudard/CVE-2026-30945-PoC.svg)

## CVE-2026-30944
 StudioCMS is a server-side-rendered, Astro native, headless content management system. Prior to 0.4.0, the /studiocms_api/dashboard/api-tokens endpoint allows any authenticated user (at least Editor) to generate API tokens for any other user, including owner and admin accounts. The endpoint fails to validate whether the requesting user is authorized to create tokens on behalf of the target user ID, resulting in a full privilege escalation. This vulnerability is fixed in 0.4.0.



- [https://github.com/FilipeGaudard/CVE-2026-30944-PoC](https://github.com/FilipeGaudard/CVE-2026-30944-PoC) :  ![starts](https://img.shields.io/github/stars/FilipeGaudard/CVE-2026-30944-PoC.svg) ![forks](https://img.shields.io/github/forks/FilipeGaudard/CVE-2026-30944-PoC.svg)

## CVE-2026-30863
 Parse Server is an open source backend that can be deployed to any infrastructure that can run Node.js. Prior to versions 8.6.10 and 9.5.0-alpha.11, the Google, Apple, and Facebook authentication adapters use JWT verification to validate identity tokens. When the adapter's audience configuration option is not set (clientId for Google/Apple, appIds for Facebook), JWT verification silently skips audience claim validation. This allows an attacker to use a validly signed JWT issued for a different application to authenticate as any user on the target Parse Server. This issue has been patched in versions 8.6.10 and 9.5.0-alpha.11.



- [https://github.com/Worthes/CVE-2026-30863-Exploit](https://github.com/Worthes/CVE-2026-30863-Exploit) :  ![starts](https://img.shields.io/github/stars/Worthes/CVE-2026-30863-Exploit.svg) ![forks](https://img.shields.io/github/forks/Worthes/CVE-2026-30863-Exploit.svg)

## CVE-2026-30862
 Appsmith is a platform to build admin panels, internal tools, and dashboards. Prior to 1.96, a Critical Stored XSS vulnerability exists in the Table Widget (TableWidgetV2). The root cause is a lack of HTML sanitization in the React component rendering pipeline, allowing malicious attributes to be interpolated into the DOM. By leveraging the "Invite Users" feature, an attacker with a regular user account (user@gmail.com) can force a System Administrator to execute a high-privileged API call (/api/v1/admin/env), resulting in a Full Administrative Account Takeover. This vulnerability is fixed in 1.96.



- [https://github.com/drkim-dev/CVE-2026-30862](https://github.com/drkim-dev/CVE-2026-30862) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-30862.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-30862.svg)

## CVE-2026-30824
 Flowise is a drag & drop user interface to build a customized large language model flow. Prior to version 3.0.13, the NVIDIA NIM router (/api/v1/nvidia-nim/*) is whitelisted in the global authentication middleware, allowing unauthenticated access to privileged container management and token generation endpoints. This issue has been patched in version 3.0.13.



- [https://github.com/dylvie/CVE-2026-30824-Flowise-NVIDIA-NIM-Authentication](https://github.com/dylvie/CVE-2026-30824-Flowise-NVIDIA-NIM-Authentication) :  ![starts](https://img.shields.io/github/stars/dylvie/CVE-2026-30824-Flowise-NVIDIA-NIM-Authentication.svg) ![forks](https://img.shields.io/github/forks/dylvie/CVE-2026-30824-Flowise-NVIDIA-NIM-Authentication.svg)

## CVE-2026-30741
 A remote code execution (RCE) vulnerability in OpenClaw Agent Platform v2026.2.6 allows attackers to execute arbitrary code via a Request-Side prompt injection attack.



- [https://github.com/Named1ess/CVE-2026-30741](https://github.com/Named1ess/CVE-2026-30741) :  ![starts](https://img.shields.io/github/stars/Named1ess/CVE-2026-30741.svg) ![forks](https://img.shields.io/github/forks/Named1ess/CVE-2026-30741.svg)

## CVE-2026-30695
 A Cross-Site Scripting (XSS) vulnerability exists in the web-based configuration interface of Zucchetti Axess access control devices, including XA4, X3/X3BIO, X4, X7, and XIO / i-door / i-door+. The vulnerability is caused by improper sanitization of user-supplied input in the dirBrowse parameter of the /file_manager.cgi endpoint.



- [https://github.com/iremnurylmz/CVE-2026-30695](https://github.com/iremnurylmz/CVE-2026-30695) :  ![starts](https://img.shields.io/github/stars/iremnurylmz/CVE-2026-30695.svg) ![forks](https://img.shields.io/github/forks/iremnurylmz/CVE-2026-30695.svg)

## CVE-2026-30655
 SQL injection in Solicitante::resetaSenha() in esiclivre/esiclivre v0.2.2 and earlier allows unauthenticated remote attackers to gain unauthorized access to sensitive information via the cpfcnpj parameter in /reset/index.php



- [https://github.com/brynax/CVE-2026-30655](https://github.com/brynax/CVE-2026-30655) :  ![starts](https://img.shields.io/github/stars/brynax/CVE-2026-30655.svg) ![forks](https://img.shields.io/github/forks/brynax/CVE-2026-30655.svg)

## CVE-2026-30615
 A prompt injection vulnerability in Windsurf 1.9544.26 allows remote attackers to execute arbitrary commands on a victim system. When Windsurf processes attacker-controlled HTML content, malicious instructions can cause unauthorized modification of the local MCP configuration and automatic registration of a malicious MCP STDIO server, resulting in execution of arbitrary commands without further user interaction. Successful exploitation may allow attackers to execute commands on behalf of the user, persist malicious MCP configuration changes, and access sensitive information exposed through the application.



- [https://github.com/TreRB/ai-ide-config-guard](https://github.com/TreRB/ai-ide-config-guard) :  ![starts](https://img.shields.io/github/stars/TreRB/ai-ide-config-guard.svg) ![forks](https://img.shields.io/github/forks/TreRB/ai-ide-config-guard.svg)

## CVE-2026-30480
 A Local File Inclusion (LFI) vulnerability in the NFSen module (nfsen.inc.php) of LibreNMS 22.11.0-23-gd091788f2 allows authenticated attackers to include arbitrary PHP files from the server filesystem via path traversal sequences in the nfsen parameter.



- [https://github.com/parlakbarann/CVE-2026-30480](https://github.com/parlakbarann/CVE-2026-30480) :  ![starts](https://img.shields.io/github/stars/parlakbarann/CVE-2026-30480.svg) ![forks](https://img.shields.io/github/forks/parlakbarann/CVE-2026-30480.svg)

## CVE-2026-30368
 A client-side authorization flaw in Lightspeed Classroom v5.1.2.1763770643 allows unauthenticated attackers to impersonate users by bypassing integrity checks and abusing client-generated authorization tokens, leading to unauthorized control and monitoring of student devices.



- [https://github.com/truekas/ls-poc](https://github.com/truekas/ls-poc) :  ![starts](https://img.shields.io/github/stars/truekas/ls-poc.svg) ![forks](https://img.shields.io/github/forks/truekas/ls-poc.svg)

## CVE-2026-30345
 A zip slip vulnerability in the Admin import functionality of CTFd v3.8.1-18-gdb5a18c4 allows attackers to write arbitrary files outside the intended directories via supplying a crafted import.



- [https://github.com/syphonetic/CVE-2026-30345](https://github.com/syphonetic/CVE-2026-30345) :  ![starts](https://img.shields.io/github/stars/syphonetic/CVE-2026-30345.svg) ![forks](https://img.shields.io/github/forks/syphonetic/CVE-2026-30345.svg)

## CVE-2026-30332
 A Time-of-Check to Time-of-Use (TOCTOU) race condition vulnerability in Balena Etcher for Windows prior to v2.1.4 allows attackers to escalate privileges and execute arbitrary code via replacing a legitimate script with a crafted payload during the flashing process.



- [https://github.com/B1tBreaker/CVE-2026-30332](https://github.com/B1tBreaker/CVE-2026-30332) :  ![starts](https://img.shields.io/github/stars/B1tBreaker/CVE-2026-30332.svg) ![forks](https://img.shields.io/github/forks/B1tBreaker/CVE-2026-30332.svg)

## CVE-2026-30082
 Multiple stored cross-site scripting (XSS) vulnerabilities in the Edit feature of the Software Package List page of IngEstate Server v11.14.0 allow attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the About application, What's news, or Release note parameters.



- [https://github.com/Cr0wld3r/CVE-2026-30082](https://github.com/Cr0wld3r/CVE-2026-30082) :  ![starts](https://img.shields.io/github/stars/Cr0wld3r/CVE-2026-30082.svg) ![forks](https://img.shields.io/github/forks/Cr0wld3r/CVE-2026-30082.svg)

## CVE-2026-30048
 A stored cross-site scripting (XSS) vulnerability exists in the NotChatbot WebChat widget thru 1.4.4. User-supplied input is not properly sanitized before being stored and rendered in the chat conversation history. This allows an attacker to inject arbitrary JavaScript code which is executed when the chat history is reloaded. The issue is reproducible across multiple independent implementations of the widget, indicating that the vulnerability resides in the product itself rather than in a specific website configuration.



- [https://github.com/0xN4no/CVE-2026-30048](https://github.com/0xN4no/CVE-2026-30048) :  ![starts](https://img.shields.io/github/stars/0xN4no/CVE-2026-30048.svg) ![forks](https://img.shields.io/github/forks/0xN4no/CVE-2026-30048.svg)

## CVE-2026-29971
 A reflected cross-site scripting (XSS) vulnerability exists in WebFileSys version before 2.32.0 and fixed in v.2.32.0. User-controlled input is reflected into HTML and JavaScript contexts without proper output encoding, allowing arbitrary JavaScript execution in the victim's browser via the ftpBackup functionality, authentication input handling, search functionality, and error message rendering components



- [https://github.com/Tharooon/CVE-2026-29971](https://github.com/Tharooon/CVE-2026-29971) :  ![starts](https://img.shields.io/github/stars/Tharooon/CVE-2026-29971.svg) ![forks](https://img.shields.io/github/forks/Tharooon/CVE-2026-29971.svg)

- [https://github.com/tharunchidurala-cyber/BACkupCVE-2026-29971](https://github.com/tharunchidurala-cyber/BACkupCVE-2026-29971) :  ![starts](https://img.shields.io/github/stars/tharunchidurala-cyber/BACkupCVE-2026-29971.svg) ![forks](https://img.shields.io/github/forks/tharunchidurala-cyber/BACkupCVE-2026-29971.svg)

## CVE-2026-29955
 The `/registercrd` endpoint in KubePlus 4.14 in the kubeconfiggenerator component is vulnerable to command injection. The component uses `subprocess.Popen()` with `shell=True` parameter to execute shell commands, and the user-supplied `chartName` parameter is directly concatenated into the command string without any sanitization or validation. An attacker can inject arbitrary shell commands by crafting a malicious `chartName` parameter value.



- [https://github.com/b0b0haha/CVE-2026-29955](https://github.com/b0b0haha/CVE-2026-29955) :  ![starts](https://img.shields.io/github/stars/b0b0haha/CVE-2026-29955.svg) ![forks](https://img.shields.io/github/forks/b0b0haha/CVE-2026-29955.svg)

## CVE-2026-29954
 In KubePlus 4.1.4, the mutating webhook and kubeconfiggenerator components have an SSRF vulnerability when processing the chartURL field of ResourceComposition resources. The field is only URL-encoded without validating the target address. More critically, when kubeconfiggenerator uses wget to download charts, the chartURL is directly concatenated into the command, allowing attackers to inject wget's `--header` option to achieve arbitrary HTTP header injection.



- [https://github.com/b0b0haha/CVE-2026-29954](https://github.com/b0b0haha/CVE-2026-29954) :  ![starts](https://img.shields.io/github/stars/b0b0haha/CVE-2026-29954.svg) ![forks](https://img.shields.io/github/forks/b0b0haha/CVE-2026-29954.svg)

## CVE-2026-29923
 The pstrip64.sys driver in EnTech Taiwan PowerStrip =3.90.736 allows local users to escalate privileges to SYSTEM via a crafted IOCTL request enabling unprivileged users to map arbitrary physical memory into their address space and modify critical kernel structures.



- [https://github.com/athenasec16/CVE-2026-29923](https://github.com/athenasec16/CVE-2026-29923) :  ![starts](https://img.shields.io/github/stars/athenasec16/CVE-2026-29923.svg) ![forks](https://img.shields.io/github/forks/athenasec16/CVE-2026-29923.svg)

- [https://github.com/Smarttfoxx/CVE-2026-29923](https://github.com/Smarttfoxx/CVE-2026-29923) :  ![starts](https://img.shields.io/github/stars/Smarttfoxx/CVE-2026-29923.svg) ![forks](https://img.shields.io/github/forks/Smarttfoxx/CVE-2026-29923.svg)

## CVE-2026-29909
 MRCMS V3.1.2 contains an unauthenticated directory enumeration vulnerability in the file management module. The /admin/file/list.do endpoint lacks authentication controls and proper input validation, allowing remote attackers to enumerate directory contents on the server without any credentials.



- [https://github.com/qflksheep/CVE-2026-29909-MRCMS-vulnerability](https://github.com/qflksheep/CVE-2026-29909-MRCMS-vulnerability) :  ![starts](https://img.shields.io/github/stars/qflksheep/CVE-2026-29909-MRCMS-vulnerability.svg) ![forks](https://img.shields.io/github/forks/qflksheep/CVE-2026-29909-MRCMS-vulnerability.svg)

## CVE-2026-29861
 PHP-MYSQL-User-Login-System v1.0 was discovered to contain a SQL injection vulnerability via the username parameter at login.php.



- [https://github.com/amanyadav78/CVE-2026-29861](https://github.com/amanyadav78/CVE-2026-29861) :  ![starts](https://img.shields.io/github/stars/amanyadav78/CVE-2026-29861.svg) ![forks](https://img.shields.io/github/forks/amanyadav78/CVE-2026-29861.svg)

## CVE-2026-29786
 node-tar is a full-featured Tar for Node.js. Prior to version 7.5.10, tar can be tricked into creating a hardlink that points outside the extraction directory by using a drive-relative link target such as C:../target.txt, which enables file overwrite outside cwd during normal tar.x() extraction. This issue has been patched in version 7.5.10.



- [https://github.com/Jvr2022/CVE-2026-29786](https://github.com/Jvr2022/CVE-2026-29786) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-29786.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-29786.svg)

- [https://github.com/Rohitberiwala/NodeJS-Tar-Symlink-Exploit-CVE-2026-29786](https://github.com/Rohitberiwala/NodeJS-Tar-Symlink-Exploit-CVE-2026-29786) :  ![starts](https://img.shields.io/github/stars/Rohitberiwala/NodeJS-Tar-Symlink-Exploit-CVE-2026-29786.svg) ![forks](https://img.shields.io/github/forks/Rohitberiwala/NodeJS-Tar-Symlink-Exploit-CVE-2026-29786.svg)

## CVE-2026-29781
 Sliver is a command and control framework that uses a custom Wireguard netstack. In versions from 1.7.3 and prior, a vulnerability exists in the Sliver C2 server's Protobuf unmarshalling logic due to a systemic lack of nil-pointer validation. By extracting valid implant credentials and omitting nested fields in a signed message, an authenticated actor can trigger an unhandled runtime panic. Because the mTLS, WireGuard, and DNS transport layers lack the panic recovery middleware present in the HTTP transport, this results in a global process termination. While requiring post-authentication access (a captured implant), this flaw effectively acts as an infrastructure "kill-switch," instantly severing all active sessions across the entire fleet and requiring a manual server restart to restore operations. At time of publication, there are no publicly available patches.



- [https://github.com/skoveit/CVE-2026-29781](https://github.com/skoveit/CVE-2026-29781) :  ![starts](https://img.shields.io/github/stars/skoveit/CVE-2026-29781.svg) ![forks](https://img.shields.io/github/forks/skoveit/CVE-2026-29781.svg)

## CVE-2026-29780
 eml_parser serves as a python module for parsing eml files and returning various information found in the e-mail as well as computed information. Prior to version 2.0.1, the official example script examples/recursively_extract_attachments.py contains a path traversal vulnerability that allows arbitrary file write outside the intended output directory. Attachment filenames extracted from parsed emails are directly used to construct output file paths without any sanitization, allowing an attacker-controlled filename to escape the target directory. This issue has been patched in version 2.0.1.



- [https://github.com/redyank/CVE-2026-29780](https://github.com/redyank/CVE-2026-29780) :  ![starts](https://img.shields.io/github/stars/redyank/CVE-2026-29780.svg) ![forks](https://img.shields.io/github/forks/redyank/CVE-2026-29780.svg)

## CVE-2026-29628
 A stack overflow in the experimental/tinyobj_loader_opt.h file of tinyobjloader commit d56555b allows attackers to cause a Denial of Service (DoS) via supplying a crafted .mtl file.



- [https://github.com/kiyochii/CVE-2026-29628](https://github.com/kiyochii/CVE-2026-29628) :  ![starts](https://img.shields.io/github/stars/kiyochii/CVE-2026-29628.svg) ![forks](https://img.shields.io/github/forks/kiyochii/CVE-2026-29628.svg)

## CVE-2026-29598
 Multiple stored cross-site scripting (XSS) vulnerabilities in the submit_add_user.asp endpoint of DDSN Interactive Acora CMS v10.7.1 allow attackers to execute arbitrary web scripts or HTML via injecting a crafted payload into the First Name and Last Name parameters.



- [https://github.com/padayali-JD/CVE-2026-29598](https://github.com/padayali-JD/CVE-2026-29598) :  ![starts](https://img.shields.io/github/stars/padayali-JD/CVE-2026-29598.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/CVE-2026-29598.svg)

## CVE-2026-29597
 DDSN Interactive cm3 Acora CMS version 10.7.1 contains an improper access control vulnerability. An editor-privileged user can access sensitive configuration files by force browsing the “/Admin/file_manager/file_details.asp” endpoint and manipulating the “file” parameter. By referencing specific files (e.g., cm3.xml), the attacker can retrieve system administrator credentials, SMTP settings, database credentials, and other confidential information. The exposure of this information can lead to full administrative access to the CMS, unauthorized access to email services, compromise of backend databases, lateral movement within the network, and long-term persistence by an attacker. This access control bypass poses a critical risk of account takeover, privilege escalation, and systemic compromise of the affected application and its associated infrastructure.



- [https://github.com/padayali-JD/CVE-2026-29597](https://github.com/padayali-JD/CVE-2026-29597) :  ![starts](https://img.shields.io/github/stars/padayali-JD/CVE-2026-29597.svg) ![forks](https://img.shields.io/github/forks/padayali-JD/CVE-2026-29597.svg)

## CVE-2026-29187
 OpenEMR is a free and open source electronic health records and medical practice management application. Prior to version 8.0.0.3, a Blind SQL Injection vulnerability exists in the Patient Search functionality (/interface/new/new_search_popup.php). The vulnerability allows an authenticated attacker to execute arbitrary SQL commands by manipulating the HTTP parameter keys rather than the values. Version 8.0.0.3 contains a patch.



- [https://github.com/ChrisSub08/CVE-2026-29187_SqlInjectionVulnerabilityOpenEMR7.0.4](https://github.com/ChrisSub08/CVE-2026-29187_SqlInjectionVulnerabilityOpenEMR7.0.4) :  ![starts](https://img.shields.io/github/stars/ChrisSub08/CVE-2026-29187_SqlInjectionVulnerabilityOpenEMR7.0.4.svg) ![forks](https://img.shields.io/github/forks/ChrisSub08/CVE-2026-29187_SqlInjectionVulnerabilityOpenEMR7.0.4.svg)

## CVE-2026-29145
 CLIENT_CERT authentication does not fail as expected for some scenarios when soft fail is disabled vulnerability in Apache Tomcat, Apache Tomcat Native.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.18, from 10.1.0-M7 through 10.1.52, from 9.0.83 through 9.0.115; Apache Tomcat Native: from 1.1.23 through 1.1.34, from 1.2.0 through 1.2.39, from 1.3.0 through 1.3.6, from 2.0.0 through 2.0.13.

Users are recommended to upgrade to version Tomcat Native 1.3.7 or 2.0.14 and Tomcat 11.0.20, 10.1.53 and 9.0.116, which fix the issue.



- [https://github.com/gregk4sec/cve-2026-29145](https://github.com/gregk4sec/cve-2026-29145) :  ![starts](https://img.shields.io/github/stars/gregk4sec/cve-2026-29145.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/cve-2026-29145.svg)

- [https://github.com/sancliffe/CVE-2026-29145-Tester](https://github.com/sancliffe/CVE-2026-29145-Tester) :  ![starts](https://img.shields.io/github/stars/sancliffe/CVE-2026-29145-Tester.svg) ![forks](https://img.shields.io/github/forks/sancliffe/CVE-2026-29145-Tester.svg)

## CVE-2026-29059
 Windmill is an open-source developer platform for internal code: APIs, background jobs, workflows and UIs. Prior to version 1.603.3, an unauthenticated path traversal vulnerability exists in Windmill's get_log_file endpoint "(/api/w/{workspace}/jobs_u/get_log_file/{filename})". The filename parameter is concatenated into a file path without sanitization, allowing an attacker to read arbitrary files on the server using ../ sequences. This issue has been patched in version 1.603.3.



- [https://github.com/Chocapikk/Windfall](https://github.com/Chocapikk/Windfall) :  ![starts](https://img.shields.io/github/stars/Chocapikk/Windfall.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/Windfall.svg)

## CVE-2026-29057
 Next.js is a React framework for building full-stack web applications. Starting in version 9.5.0 and prior to versions 15.5.13 and 16.1.7, when Next.js rewrites proxy traffic to an external backend, a crafted `DELETE`/`OPTIONS` request using `Transfer-Encoding: chunked` could trigger request boundary disagreement between the proxy and backend. This could allow request smuggling through rewritten routes. An attacker could smuggle a second request to unintended backend routes (for example, internal/admin endpoints), bypassing assumptions that only the configured rewrite destination/path is reachable. This does not impact applications hosted on providers that handle rewrites at the CDN level, such as Vercel.  The vulnerability originated in an upstream library vendored by Next.js. It is fixed in Next.js 15.5.13 and 16.1.7 by updating that dependency’s behavior so `content-length: 0` is added only when both `content-length` and `transfer-encoding` are absent, and `transfer-encoding` is no longer removed in that code path. If upgrading is not immediately possible, block chunked `DELETE`/`OPTIONS` requests on rewritten routes at the edge/proxy, and/or enforce authentication/authorization on backend routes.



- [https://github.com/Nayekah/Next.js-Proof-of-Concept](https://github.com/Nayekah/Next.js-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/Nayekah/Next.js-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/Nayekah/Next.js-Proof-of-Concept.svg)

## CVE-2026-29053
 Ghost is a Node.js content management system. From version 0.7.2 to 6.19.0, specifically crafted malicious themes can execute arbitrary code on the server running Ghost. This issue has been patched in version 6.19.1.



- [https://github.com/AC8999/CVE-2026-29053](https://github.com/AC8999/CVE-2026-29053) :  ![starts](https://img.shields.io/github/stars/AC8999/CVE-2026-29053.svg) ![forks](https://img.shields.io/github/forks/AC8999/CVE-2026-29053.svg)

- [https://github.com/rootxran/CVE-2026-29053](https://github.com/rootxran/CVE-2026-29053) :  ![starts](https://img.shields.io/github/stars/rootxran/CVE-2026-29053.svg) ![forks](https://img.shields.io/github/forks/rootxran/CVE-2026-29053.svg)

## CVE-2026-29041
 Chamilo is a learning management system. Prior to version 1.11.34, Chamilo LMS is affected by an authenticated remote code execution vulnerability caused by improper validation of uploaded files. The application relies solely on MIME-type verification when handling file uploads and does not adequately validate file extensions or enforce safe server-side storage restrictions. As a result, an authenticated low-privileged user can upload a crafted file containing executable code and subsequently execute arbitrary commands on the server. This issue has been patched in version 1.11.34.



- [https://github.com/kx00007/CVE-2026-29041](https://github.com/kx00007/CVE-2026-29041) :  ![starts](https://img.shields.io/github/stars/kx00007/CVE-2026-29041.svg) ![forks](https://img.shields.io/github/forks/kx00007/CVE-2026-29041.svg)

## CVE-2026-29000
 pac4j-jwt versions prior to 4.5.9, 5.7.9, and 6.3.3 contain an authentication bypass vulnerability in JwtAuthenticator when processing encrypted JWTs that allows remote attackers to forge authentication tokens. Attackers who possess the server's RSA public key can create a JWE-wrapped PlainJWT with arbitrary subject and role claims, bypassing signature verification to authenticate as any user including administrators.



- [https://github.com/kernelzeroday/CVE-2026-29000](https://github.com/kernelzeroday/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/kernelzeroday/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/kernelzeroday/CVE-2026-29000.svg)

- [https://github.com/RootX111/cve-2026-29000](https://github.com/RootX111/cve-2026-29000) :  ![starts](https://img.shields.io/github/stars/RootX111/cve-2026-29000.svg) ![forks](https://img.shields.io/github/forks/RootX111/cve-2026-29000.svg)

- [https://github.com/otuva/CVE-2026-29000](https://github.com/otuva/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/otuva/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/otuva/CVE-2026-29000.svg)

- [https://github.com/manbahadurthapa1248/CVE-2026-29000---pac4j-jwt-Authentication-Bypass-PoC](https://github.com/manbahadurthapa1248/CVE-2026-29000---pac4j-jwt-Authentication-Bypass-PoC) :  ![starts](https://img.shields.io/github/stars/manbahadurthapa1248/CVE-2026-29000---pac4j-jwt-Authentication-Bypass-PoC.svg) ![forks](https://img.shields.io/github/forks/manbahadurthapa1248/CVE-2026-29000---pac4j-jwt-Authentication-Bypass-PoC.svg)

- [https://github.com/strikoder/CVE-2026-29000-pac4j-jwt](https://github.com/strikoder/CVE-2026-29000-pac4j-jwt) :  ![starts](https://img.shields.io/github/stars/strikoder/CVE-2026-29000-pac4j-jwt.svg) ![forks](https://img.shields.io/github/forks/strikoder/CVE-2026-29000-pac4j-jwt.svg)

- [https://github.com/ClayOfGilgamesh/CVE-2026-29000](https://github.com/ClayOfGilgamesh/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/ClayOfGilgamesh/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/ClayOfGilgamesh/CVE-2026-29000.svg)

- [https://github.com/zF-tm/CVE-2026-29000](https://github.com/zF-tm/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/zF-tm/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/zF-tm/CVE-2026-29000.svg)

- [https://github.com/jake-young-dev/CVE-2026-29000](https://github.com/jake-young-dev/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/jake-young-dev/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/jake-young-dev/CVE-2026-29000.svg)

- [https://github.com/Crims-on/CVE-2026-29000](https://github.com/Crims-on/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/Crims-on/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/Crims-on/CVE-2026-29000.svg)

- [https://github.com/yasirr10/CVE-2026-29000](https://github.com/yasirr10/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/yasirr10/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/yasirr10/CVE-2026-29000.svg)

- [https://github.com/0xW1LD/CVE-2026-29000](https://github.com/0xW1LD/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/0xW1LD/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/0xW1LD/CVE-2026-29000.svg)

- [https://github.com/cipher1x1/CVE-2026-29000](https://github.com/cipher1x1/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/cipher1x1/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/cipher1x1/CVE-2026-29000.svg)

- [https://github.com/Gajraj238/CVE-2026-29000](https://github.com/Gajraj238/CVE-2026-29000) :  ![starts](https://img.shields.io/github/stars/Gajraj238/CVE-2026-29000.svg) ![forks](https://img.shields.io/github/forks/Gajraj238/CVE-2026-29000.svg)

- [https://github.com/FranzAlvis/Cve_2026_29000_exploit](https://github.com/FranzAlvis/Cve_2026_29000_exploit) :  ![starts](https://img.shields.io/github/stars/FranzAlvis/Cve_2026_29000_exploit.svg) ![forks](https://img.shields.io/github/forks/FranzAlvis/Cve_2026_29000_exploit.svg)

- [https://github.com/rootdirective-sec/CVE-2026-29000-Lab](https://github.com/rootdirective-sec/CVE-2026-29000-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-29000-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-29000-Lab.svg)

- [https://github.com/PtechAmanja/CVE-2026-29000-pac4j-jwt-auth-bypass](https://github.com/PtechAmanja/CVE-2026-29000-pac4j-jwt-auth-bypass) :  ![starts](https://img.shields.io/github/stars/PtechAmanja/CVE-2026-29000-pac4j-jwt-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/PtechAmanja/CVE-2026-29000-pac4j-jwt-auth-bypass.svg)

- [https://github.com/alihussainzada/CVE-2026-29000-Python-PoC-pac4j-JWT-AuthenticationBypass-Poc](https://github.com/alihussainzada/CVE-2026-29000-Python-PoC-pac4j-JWT-AuthenticationBypass-Poc) :  ![starts](https://img.shields.io/github/stars/alihussainzada/CVE-2026-29000-Python-PoC-pac4j-JWT-AuthenticationBypass-Poc.svg) ![forks](https://img.shields.io/github/forks/alihussainzada/CVE-2026-29000-Python-PoC-pac4j-JWT-AuthenticationBypass-Poc.svg)

- [https://github.com/ledksv/Principal-HackTheBox](https://github.com/ledksv/Principal-HackTheBox) :  ![starts](https://img.shields.io/github/stars/ledksv/Principal-HackTheBox.svg) ![forks](https://img.shields.io/github/forks/ledksv/Principal-HackTheBox.svg)

## CVE-2026-28858
 A buffer overflow was addressed with improved bounds checking. This issue is fixed in iOS 26.4 and iPadOS 26.4. A remote user may be able to cause unexpected system termination or corrupt kernel memory.



- [https://github.com/kaleth4/CVE-2026-28858](https://github.com/kaleth4/CVE-2026-28858) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-28858.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-28858.svg)

## CVE-2026-28767
 A specific administrative endpoint notifications is accessible without proper authentication.



- [https://github.com/MichaelAdamGroberman/CVE-2026-28767](https://github.com/MichaelAdamGroberman/CVE-2026-28767) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2026-28767.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2026-28767.svg)

## CVE-2026-28766
 A specific endpoint exposes all user account information for registered Gardyn users without requiring authentication.



- [https://github.com/MichaelAdamGroberman/CVE-2026-28766](https://github.com/MichaelAdamGroberman/CVE-2026-28766) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2026-28766.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2026-28766.svg)

## CVE-2026-28466
 OpenClaw versions prior to 2026.2.14 contain a vulnerability in the gateway in which it fails to sanitize internal approval fields in node.invoke parameters, allowing authenticated clients to bypass exec approval gating for system.run commands. Attackers with valid gateway credentials can inject approval control fields to execute arbitrary commands on connected node hosts, potentially compromising developer workstations and CI runners.



- [https://github.com/Orioning/CVE-2026-28466](https://github.com/Orioning/CVE-2026-28466) :  ![starts](https://img.shields.io/github/stars/Orioning/CVE-2026-28466.svg) ![forks](https://img.shields.io/github/forks/Orioning/CVE-2026-28466.svg)

## CVE-2026-28372
 telnetd in GNU inetutils through 2.7 allows privilege escalation that can be exploited by abusing systemd service credentials support added to the login(1) implementation of util-linux in release 2.40. This is related to client control over the CREDENTIALS_DIRECTORY environment variable, and requires an unprivileged local user to create a login.noauth file.



- [https://github.com/Rohitberiwala/CVE-2026-28372-telnetd-Privilege-Escalation](https://github.com/Rohitberiwala/CVE-2026-28372-telnetd-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/Rohitberiwala/CVE-2026-28372-telnetd-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/Rohitberiwala/CVE-2026-28372-telnetd-Privilege-Escalation.svg)

- [https://github.com/mbanyamer/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation](https://github.com/mbanyamer/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation.svg)

- [https://github.com/kalibb/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation-main](https://github.com/kalibb/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation-main) :  ![starts](https://img.shields.io/github/stars/kalibb/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation-main.svg) ![forks](https://img.shields.io/github/forks/kalibb/CVE-2026-28372-GNU-inetutils-telnetd-Privilege-Escalation-main.svg)

## CVE-2026-28363
 In OpenClaw before 2026.2.23, tools.exec.safeBins validation for sort could be bypassed via GNU long-option abbreviations (such as --compress-prog) in allowlist mode, leading to approval-free execution paths that were intended to require approval. Only an exact string such as --compress-program was denied.



- [https://github.com/kaleth4/CVE-2026-28363](https://github.com/kaleth4/CVE-2026-28363) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-28363.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-28363.svg)

## CVE-2026-28289
 FreeScout is a free help desk and shared inbox built with PHP's Laravel framework. A patch bypass vulnerability for CVE-2026-27636 in FreeScout 1.8.206 and earlier allows any authenticated user with file upload permissions to achieve Remote Code Execution (RCE) on the server by uploading a malicious .htaccess file using a zero-width space character prefix to bypass the security check. The vulnerability exists in the sanitizeUploadedFileName() function in app/Http/Helper.php. The function contains a Time-of-Check to Time-of-Use (TOCTOU) flaw where the dot-prefix check occurs before sanitization removes invisible characters. This vulnerability is fixed in 1.8.207.



- [https://github.com/0xBlackash/CVE-2026-28289](https://github.com/0xBlackash/CVE-2026-28289) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-28289.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-28289.svg)

## CVE-2026-28286
 ZimaOS is a fork of CasaOS, an operating system for Zima devices and x86-64 systems with UEFI. In version 1.5.2-beta3, the application enforces restrictions in the frontend/UI to prevent users from creating files or folders in internal OS paths. However, when interacting directly with the API, the restrictions are bypass-able. By sending a crafted request targeting paths like /etc, /usr, or other sensitive system directories, the API successfully creates files or directories in locations where normal users should have no write access. This indicates that the API does not properly validate the target path, allowing unauthorized operations on critical system directories. No known patch is publicly available.



- [https://github.com/Rushi9/zimaos-cve-2026-28286-arbitrary-file-write](https://github.com/Rushi9/zimaos-cve-2026-28286-arbitrary-file-write) :  ![starts](https://img.shields.io/github/stars/Rushi9/zimaos-cve-2026-28286-arbitrary-file-write.svg) ![forks](https://img.shields.io/github/forks/Rushi9/zimaos-cve-2026-28286-arbitrary-file-write.svg)

## CVE-2026-27978
 Next.js is a React framework for building full-stack web applications. Starting in version 16.0.1 and prior to version 16.1.7, `origin: null` was treated as a "missing" origin during Server Action CSRF validation. As a result, requests from opaque contexts (such as sandboxed iframes) could bypass origin verification instead of being validated as cross-origin requests. An attacker could induce a victim browser to submit Server Actions from a sandboxed context, potentially executing state-changing actions with victim credentials (CSRF). This is fixed in version 16.1.7 by treating `'null'` as an explicit origin value and enforcing host/origin checks unless `'null'` is explicitly allowlisted in `experimental.serverActions.allowedOrigins`. If upgrading is not immediately possible, add CSRF tokens for sensitive Server Actions, prefer `SameSite=Strict` on sensitive auth cookies, and/or do not allow `'null'` in `serverActions.allowedOrigins` unless intentionally required and additionally protected.



- [https://github.com/Nayekah/Next.js-Proof-of-Concept](https://github.com/Nayekah/Next.js-Proof-of-Concept) :  ![starts](https://img.shields.io/github/stars/Nayekah/Next.js-Proof-of-Concept.svg) ![forks](https://img.shields.io/github/forks/Nayekah/Next.js-Proof-of-Concept.svg)

## CVE-2026-27966
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to version 1.8.0, the CSV Agent node in Langflow hardcodes `allow_dangerous_code=True`, which automatically exposes LangChain’s Python REPL tool (`python_repl_ast`). As a result, an attacker can execute arbitrary Python and OS commands on the server via prompt injection, leading to full Remote Code Execution (RCE). Version 1.8.0 fixes the issue.



- [https://github.com/Anon-Cyber-Team/CVE-2026-27966--RCE-in-Langflow](https://github.com/Anon-Cyber-Team/CVE-2026-27966--RCE-in-Langflow) :  ![starts](https://img.shields.io/github/stars/Anon-Cyber-Team/CVE-2026-27966--RCE-in-Langflow.svg) ![forks](https://img.shields.io/github/forks/Anon-Cyber-Team/CVE-2026-27966--RCE-in-Langflow.svg)

## CVE-2026-27959
 Koa is middleware for Node.js using ES2017 async functions. Prior to versions 3.1.2 and 2.16.4, Koa's `ctx.hostname` API performs naive parsing of the HTTP Host header, extracting everything before the first colon without validating the input conforms to RFC 3986 hostname syntax. When a malformed Host header containing a `@` symbol is received, `ctx.hostname` returns `evil[.]com` - an attacker-controlled value. Applications using `ctx.hostname` for URL generation, password reset links, email verification URLs, or routing decisions are vulnerable to Host header injection attacks. Versions 3.1.2 and 2.16.4 fix the issue.



- [https://github.com/mlouazir/CVE-2026-27959-mini-lab](https://github.com/mlouazir/CVE-2026-27959-mini-lab) :  ![starts](https://img.shields.io/github/stars/mlouazir/CVE-2026-27959-mini-lab.svg) ![forks](https://img.shields.io/github/forks/mlouazir/CVE-2026-27959-mini-lab.svg)

## CVE-2026-27944
 Nginx UI is a web user interface for the Nginx web server. Prior to version 2.3.3, the /api/backup endpoint is accessible without authentication and discloses the encryption keys required to decrypt the backup in the X-Backup-Security response header. This allows an unauthenticated attacker to download a full system backup containing sensitive data (user credentials, session tokens, SSL private keys, Nginx configurations) and decrypt it immediately. This issue has been patched in version 2.3.3.



- [https://github.com/Skynoxk/CVE-2026-27944](https://github.com/Skynoxk/CVE-2026-27944) :  ![starts](https://img.shields.io/github/stars/Skynoxk/CVE-2026-27944.svg) ![forks](https://img.shields.io/github/forks/Skynoxk/CVE-2026-27944.svg)

- [https://github.com/NULL200OK/CVE-2026-27944](https://github.com/NULL200OK/CVE-2026-27944) :  ![starts](https://img.shields.io/github/stars/NULL200OK/CVE-2026-27944.svg) ![forks](https://img.shields.io/github/forks/NULL200OK/CVE-2026-27944.svg)

- [https://github.com/NULL200OK/-nginxui_discover](https://github.com/NULL200OK/-nginxui_discover) :  ![starts](https://img.shields.io/github/stars/NULL200OK/-nginxui_discover.svg) ![forks](https://img.shields.io/github/forks/NULL200OK/-nginxui_discover.svg)

- [https://github.com/jake-young-dev/CVE-2026-27944](https://github.com/jake-young-dev/CVE-2026-27944) :  ![starts](https://img.shields.io/github/stars/jake-young-dev/CVE-2026-27944.svg) ![forks](https://img.shields.io/github/forks/jake-young-dev/CVE-2026-27944.svg)

- [https://github.com/Goultarde/CVE-2026-27944-poc](https://github.com/Goultarde/CVE-2026-27944-poc) :  ![starts](https://img.shields.io/github/stars/Goultarde/CVE-2026-27944-poc.svg) ![forks](https://img.shields.io/github/forks/Goultarde/CVE-2026-27944-poc.svg)

- [https://github.com/karimelsheikh1/HTB-Snapped-Writeup](https://github.com/karimelsheikh1/HTB-Snapped-Writeup) :  ![starts](https://img.shields.io/github/stars/karimelsheikh1/HTB-Snapped-Writeup.svg) ![forks](https://img.shields.io/github/forks/karimelsheikh1/HTB-Snapped-Writeup.svg)

## CVE-2026-27940
 llama.cpp is an inference of several LLM models in C/C++. Prior to b8146, the gguf_init_from_file_impl() in gguf.cpp is vulnerable to an Integer overflow, leading to an undersized heap allocation. Using the subsequent fread() writes 528+ bytes of attacker-controlled data past the buffer boundary. This is a bypass of a similar bug in the same file - CVE-2025-53630, but the fix overlooked some areas. This vulnerability is fixed in b8146.



- [https://github.com/ngtuonghung/CVE-2026-27940](https://github.com/ngtuonghung/CVE-2026-27940) :  ![starts](https://img.shields.io/github/stars/ngtuonghung/CVE-2026-27940.svg) ![forks](https://img.shields.io/github/forks/ngtuonghung/CVE-2026-27940.svg)

## CVE-2026-27906
 Improper input validation in Windows Hello allows an authorized attacker to bypass a security feature locally.



- [https://github.com/ByteWraith1/CVE-2026-27906](https://github.com/ByteWraith1/CVE-2026-27906) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-27906.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-27906.svg)

## CVE-2026-27884
 NetExec is a network execution tool. Prior to version 1.5.1, the module spider_plus improperly creates the output file and folder path when saving files from SMB shares. It does not take into account that it is possible for Linux SMB shares to have path traversal characters such as `../` in them. An attacker can craft a filename in an SMB share that includes these characters, which when spider_plus crawls and downloads, can write or overwrite arbitrary files. The issue is patched in v1.5.1. As a workaround, do not run spider_plus with DOWNLOAD=true against targets.



- [https://github.com/RaynLight/CVE-2026-27884](https://github.com/RaynLight/CVE-2026-27884) :  ![starts](https://img.shields.io/github/stars/RaynLight/CVE-2026-27884.svg) ![forks](https://img.shields.io/github/forks/RaynLight/CVE-2026-27884.svg)

## CVE-2026-27876
 A chained attack via SQL Expressions and a Grafana Enterprise plugin can lead to a remote arbitrary code execution impact (RCE). This is enabled by a feature in Grafana (OSS), so all users are always recommended to update to avoid future attack vectors going this path.

Only instances with the sqlExpressions feature toggle enabled are vulnerable.

Only instances in the following version ranges are affected:

- 11.6.0 (inclusive) to 11.6.14 (exclusive): 11.6.14 has the fix. 11.5 and below are not affected.
- 12.0.0 (inclusive) to 12.1.10 (exclusive): 12.1.10 has the fix. 12.0 did not receive an update, as it is end-of-life.
- 12.2.0 (inclusive) to 12.2.8 (exclusive): 12.2.8 has the fix.
- 12.3.0 (inclusive) to 12.3.6 (exclusive): 12.3.6 has the fix.
- 12.4.0 (inclusive) to 12.4.2 (exclusive): 12.4.2 has the fix. 13.0.0 and above also have the fix: no v13 release is affected.



- [https://github.com/0xBlackash/CVE-2026-27876](https://github.com/0xBlackash/CVE-2026-27876) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-27876.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-27876.svg)

## CVE-2026-27831
 rldns is an open source DNS server. Version 1.3 has a heap-based out-of-bounds read that leads to denial of service. Version 1.4 contains a patch for the issue.



- [https://github.com/bluedragonsecurity/CVE-2026-27831-POC](https://github.com/bluedragonsecurity/CVE-2026-27831-POC) :  ![starts](https://img.shields.io/github/stars/bluedragonsecurity/CVE-2026-27831-POC.svg) ![forks](https://img.shields.io/github/forks/bluedragonsecurity/CVE-2026-27831-POC.svg)

## CVE-2026-27826
 MCP Atlassian is a Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Prior to version 0.17.0, an unauthenticated attacker who can reach the mcp-atlassian HTTP endpoint can force the server process to make outbound HTTP requests to an arbitrary attacker-controlled URL by supplying two custom HTTP headers without an `Authorization` header. No authentication is required. The vulnerability exists in the HTTP middleware and dependency injection layer — not in any MCP tool handler - making it invisible to tool-level code analysis. In cloud deployments, this could enable theft of IAM role credentials via the instance metadata endpoint (`169[.]254[.]169[.]254`). In any HTTP deployment it enables internal network reconnaissance and injection of attacker-controlled content into LLM tool results. Version 0.17.0 fixes the issue.



- [https://github.com/plutosecurity/MCPwnfluence](https://github.com/plutosecurity/MCPwnfluence) :  ![starts](https://img.shields.io/github/stars/plutosecurity/MCPwnfluence.svg) ![forks](https://img.shields.io/github/forks/plutosecurity/MCPwnfluence.svg)

## CVE-2026-27825
 MCP Atlassian is a Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Prior to version 0.17.0, the `confluence_download_attachment` MCP tool accepts a `download_path` parameter that is written to without any directory boundary enforcement. An attacker who can call this tool and supply or access a Confluence attachment with malicious content can write arbitrary content to any path the server process has write access to. Because the attacker controls both the write destination and the written content (via an uploaded Confluence attachment), this constitutes for arbitrary code execution (for example, writing a valid cron entry to `/etc/cron.d/` achieves code execution within one scheduler cycle with no server restart required). Version 0.17.0 fixes the issue.



- [https://github.com/plutosecurity/MCPwnfluence](https://github.com/plutosecurity/MCPwnfluence) :  ![starts](https://img.shields.io/github/stars/plutosecurity/MCPwnfluence.svg) ![forks](https://img.shields.io/github/forks/plutosecurity/MCPwnfluence.svg)

- [https://github.com/romain-deperne/CVE-2026-27825](https://github.com/romain-deperne/CVE-2026-27825) :  ![starts](https://img.shields.io/github/stars/romain-deperne/CVE-2026-27825.svg) ![forks](https://img.shields.io/github/forks/romain-deperne/CVE-2026-27825.svg)

## CVE-2026-27778
 The WebSocket Application Programming Interface lacks restrictions on the number of authentication requests. This absence of rate limiting may allow an attacker to conduct denial-of-service attacks by suppressing or mis-routing legitimate charger telemetry, or conduct brute-force attacks to gain unauthorized access.



- [https://github.com/KimJ6/PoC-Simulator_CVE-2026-27778](https://github.com/KimJ6/PoC-Simulator_CVE-2026-27778) :  ![starts](https://img.shields.io/github/stars/KimJ6/PoC-Simulator_CVE-2026-27778.svg) ![forks](https://img.shields.io/github/forks/KimJ6/PoC-Simulator_CVE-2026-27778.svg)

## CVE-2026-27739
 The Angular SSR is a server-rise rendering tool for Angular applications. Versions prior to 21.2.0-rc.1, 21.1.5, 20.3.17, and 19.2.21 have a Server-Side Request Forgery (SSRF) vulnerability in the Angular SSR request handling pipeline. The vulnerability exists because Angular’s internal URL reconstruction logic directly trusts and consumes user-controlled HTTP headers specifically the Host and `X-Forwarded-*` family to determine the application's base origin without any validation of the destination domain. Specifically, the framework didn't have checks for the host domain, path and character sanitization, and port validation. This vulnerability manifests in two primary ways: implicit relative URL resolution and explicit manual construction. When successfully exploited, this vulnerability allows for arbitrary internal request steering. This can lead to credential exfiltration, internal network probing, and a confidentiality breach. In order to be vulnerable, the victim application must use Angular SSR (Server-Side Rendering), the application must perform `HttpClient` requests using relative URLs OR manually construct URLs using the unvalidated `Host` / `X-Forwarded-*` headers using the `REQUEST` object, the application server must be reachable by an attacker who can influence these headers without strict validation from a front-facing proxy, and the infrastructure (Cloud, CDN, or Load Balancer) must not sanitize or validate incoming headers. Versions 21.2.0-rc.1, 21.1.5, 20.3.17, and 19.2.21 contain a patch. Some workarounds are available. Avoid using `req.headers` for URL construction. Instead, use trusted variables for base API paths. Those who cannot upgrade immediately should implement a middleware in their `server.ts` to enforce numeric ports and validated hostnames.



- [https://github.com/mr-redoo7/CVE-2026-27739-POC](https://github.com/mr-redoo7/CVE-2026-27739-POC) :  ![starts](https://img.shields.io/github/stars/mr-redoo7/CVE-2026-27739-POC.svg) ![forks](https://img.shields.io/github/forks/mr-redoo7/CVE-2026-27739-POC.svg)

## CVE-2026-27654
 NGINX Open Source and NGINX Plus have a vulnerability in the ngx_http_dav_module module that might allow an attacker to trigger a buffer overflow to the NGINX worker process; this vulnerability may result in termination of the NGINX worker process or modification of source or destination file names outside the document root. This issue affects NGINX Open Source and NGINX Plus when the configuration file uses DAV module MOVE or COPY methods, prefix location (nonregular expression location configuration), and alias directives. The integrity impact is constrained because the NGINX worker process user has low privileges and does not have access to the entire system. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.



- [https://github.com/JohannesLks/CVE-2026-27654](https://github.com/JohannesLks/CVE-2026-27654) :  ![starts](https://img.shields.io/github/stars/JohannesLks/CVE-2026-27654.svg) ![forks](https://img.shields.io/github/forks/JohannesLks/CVE-2026-27654.svg)

## CVE-2026-27639
 Mercator is an open source web application designed to enable mapping of information systems. A stored Cross-Site Scripting (XSS) vulnerability exists in Mercator prior to version 2026.02.22 due to the use of unescaped Blade directives (`{!! !!}`) in display templates. An authenticated user with the User role can inject arbitrary JavaScript payloads into fields such as "contact point" when creating or editing entities. The payload is then executed in the browser of any user who views the affected page, including administrators. Version 2026.02.22 fixes the vulnerability.



- [https://github.com/hadhub/CVE-2026-27639-Mercator-XSS](https://github.com/hadhub/CVE-2026-27639-Mercator-XSS) :  ![starts](https://img.shields.io/github/stars/hadhub/CVE-2026-27639-Mercator-XSS.svg) ![forks](https://img.shields.io/github/forks/hadhub/CVE-2026-27639-Mercator-XSS.svg)

## CVE-2026-27636
 FreeScout is a free help desk and shared inbox built with PHP's Laravel framework. Prior to version 1.8.206, FreeScout's file upload restriction list in `app/Misc/Helper.php` does not include `.htaccess` or `.user.ini` files. On Apache servers with `AllowOverride All` (a common configuration), an authenticated user can upload a `.htaccess` file to redefine how files are processed, enabling Remote Code Execution. This vulnerability can be exploited on its own or in combination with CVE-2026-27637. Version 1.8.206 fixes both vulnerabilities.



- [https://github.com/rav1010/CVE-2026-27636](https://github.com/rav1010/CVE-2026-27636) :  ![starts](https://img.shields.io/github/stars/rav1010/CVE-2026-27636.svg) ![forks](https://img.shields.io/github/forks/rav1010/CVE-2026-27636.svg)

## CVE-2026-27621
 TypiCMS is a multilingual content management system based on the Laravel framework. A Stored Cross-Site Scripting (XSS) vulnerability exists in the file upload module of TypiCMS prior to version 16.1.7. The application allows users with file upload permissions to upload SVG files. While there is a MIME type validation, the content of the SVG file is not sanitized. An attacker can upload a specially crafted SVG file containing malicious JavaScript code. When another user (such as an administrator) views or accesses this file through the application, the script executes in their browser, leading to a compromise of that user's session. The issue is exacerbated by a bug in the SVG parsing logic, which can cause a 500 error if the uploaded SVG does not contain a `viewBox` attribute. However, this does not mitigate the XSS vulnerability, as an attacker can easily include a valid `viewBox` attribute in their malicious payload. Version 16.1.7 of TypiCMS Core fixes the issue.



- [https://github.com/lukasz-rybak/CVE-2026-27621](https://github.com/lukasz-rybak/CVE-2026-27621) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-27621.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-27621.svg)

## CVE-2026-27607
 RustFS is a distributed object storage system built in Rust. In versions 1.0.0-alpha.56 through 1.0.0-alpha.82, RustFS does not validate policy conditions in presigned POST uploads (PostObject), allowing attackers to bypass content-length-range, starts-with, and Content-Type constraints. This enables unauthorized file uploads exceeding size limits, uploads to arbitrary object keys, and content-type spoofing, potentially leading to storage exhaustion, unauthorized data access, and security bypasses. Version 1.0.0-alpha.83 fixes the issue.



- [https://github.com/nikeee/CVE-2026-27607](https://github.com/nikeee/CVE-2026-27607) :  ![starts](https://img.shields.io/github/stars/nikeee/CVE-2026-27607.svg) ![forks](https://img.shields.io/github/forks/nikeee/CVE-2026-27607.svg)

## CVE-2026-27597
 Enclave is a secure JavaScript sandbox designed for safe AI agent code execution. Prior to version 2.11.1, it is possible to escape the security boundraries set by `@enclave-vm/core`, which can be used to achieve remote code execution (RCE). The issue has been fixed in version 2.11.1.



- [https://github.com/NetVanguard-cmd/CVE-2026-27597](https://github.com/NetVanguard-cmd/CVE-2026-27597) :  ![starts](https://img.shields.io/github/stars/NetVanguard-cmd/CVE-2026-27597.svg) ![forks](https://img.shields.io/github/forks/NetVanguard-cmd/CVE-2026-27597.svg)

## CVE-2026-27579
 CollabPlatform is a full-stack, real-time doc collaboration platform. In all versions of CollabPlatform, the Appwrite project used by the application is misconfigured to allow arbitrary origins in CORS responses while also permitting credentialed requests. An attacker-controlled domain can issue authenticated cross-origin requests and read sensitive user account information, including email address, account identifiers, and MFA status. The issue did not have a fix at the time of publication.



- [https://github.com/AdityaBhatt3010/CVE-2026-27579-CORS-Misconfiguration-Leading-to-Authenticated-Data-Exposure](https://github.com/AdityaBhatt3010/CVE-2026-27579-CORS-Misconfiguration-Leading-to-Authenticated-Data-Exposure) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2026-27579-CORS-Misconfiguration-Leading-to-Authenticated-Data-Exposure.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2026-27579-CORS-Misconfiguration-Leading-to-Authenticated-Data-Exposure.svg)

- [https://github.com/mbanyamer/CVE-2026-27579-CollabPlatform-Appwrite-CORS-Misconfiguration](https://github.com/mbanyamer/CVE-2026-27579-CollabPlatform-Appwrite-CORS-Misconfiguration) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-27579-CollabPlatform-Appwrite-CORS-Misconfiguration.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-27579-CollabPlatform-Appwrite-CORS-Misconfiguration.svg)

## CVE-2026-27574
 OneUptime is a solution for monitoring and managing online services. In versions 9.5.13 and below, custom JavaScript monitor feature uses Node.js's node:vm module (explicitly documented as not a security mechanism) to execute user-supplied code, allowing trivial sandbox escape via a well-known one-liner that grants full access to the underlying process. Because the probe runs with host networking and holds all cluster credentials (ONEUPTIME_SECRET, DATABASE_PASSWORD, REDIS_PASSWORD, CLICKHOUSE_PASSWORD) in its environment variables, and monitor creation is available to the lowest role (ProjectMember) with open registration enabled by default, any anonymous user can achieve full cluster compromise in about 30 seconds. This issue has been fixed in version 10.0.5.



- [https://github.com/mbanyamer/CVE-2026-27574-OneUptime-RCE](https://github.com/mbanyamer/CVE-2026-27574-OneUptime-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-27574-OneUptime-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-27574-OneUptime-RCE.svg)

## CVE-2026-27542
 Incorrect Privilege Assignment vulnerability in Rymera Web Co Pty Ltd. Woocommerce Wholesale Lead Capture woocommerce-wholesale-lead-capture allows Privilege Escalation.This issue affects Woocommerce Wholesale Lead Capture: from n/a through = 2.0.3.1.



- [https://github.com/Nxploited/CVE-2026-27542-CVE-2026-27540-](https://github.com/Nxploited/CVE-2026-27542-CVE-2026-27540-) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-27542-CVE-2026-27540-.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-27542-CVE-2026-27540-.svg)

## CVE-2026-27541
 Incorrect Privilege Assignment vulnerability in Josh Kohlbach Wholesale Suite woocommerce-wholesale-prices allows Privilege Escalation.This issue affects Wholesale Suite: from n/a through = 2.2.6.



- [https://github.com/rootdirective-sec/CVE-2026-27541-Analysis-Lab](https://github.com/rootdirective-sec/CVE-2026-27541-Analysis-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-27541-Analysis-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-27541-Analysis-Lab.svg)

## CVE-2026-27540
 Unrestricted Upload of File with Dangerous Type vulnerability in Rymera Web Co Pty Ltd. Woocommerce Wholesale Lead Capture woocommerce-wholesale-lead-capture allows Using Malicious Files.This issue affects Woocommerce Wholesale Lead Capture: from n/a through = 2.0.3.1.



- [https://github.com/DeadExpl0it/CVE-2026-27540-WordPress-Exploit-PoC](https://github.com/DeadExpl0it/CVE-2026-27540-WordPress-Exploit-PoC) :  ![starts](https://img.shields.io/github/stars/DeadExpl0it/CVE-2026-27540-WordPress-Exploit-PoC.svg) ![forks](https://img.shields.io/github/forks/DeadExpl0it/CVE-2026-27540-WordPress-Exploit-PoC.svg)

- [https://github.com/Nxploited/CVE-2026-27542-CVE-2026-27540-](https://github.com/Nxploited/CVE-2026-27542-CVE-2026-27540-) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-27542-CVE-2026-27540-.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-27542-CVE-2026-27540-.svg)

## CVE-2026-27507
 Binardat 10G08-0800GSM network switch firmware version V300SP10260209 and prior contain hard-coded administrative credentials that cannot be changed by users. Knowledge of these credentials allows full administrative access to the device.



- [https://github.com/NetVanguard-cmd/CVE-2026-27507](https://github.com/NetVanguard-cmd/CVE-2026-27507) :  ![starts](https://img.shields.io/github/stars/NetVanguard-cmd/CVE-2026-27507.svg) ![forks](https://img.shields.io/github/forks/NetVanguard-cmd/CVE-2026-27507.svg)

## CVE-2026-27483
 MindsDB is a platform for building artificial intelligence from enterprise data. Prior to version 25.9.1.1, there is a path traversal vulnerability in Mindsdb's /api/files interface, which an authenticated attacker can exploit to achieve remote command execution. The vulnerability exists in the "Upload File" module, which corresponds to the API endpoint /api/files. Since the multipart file upload does not perform security checks on the uploaded file path, an attacker can perform path traversal by using `../` sequences in the filename field. The file write operation occurs before calling clear_filename and save_file, meaning there is no filtering of filenames or file types, allowing arbitrary content to be written to any path on the server. Version 25.9.1.1 patches the issue.



- [https://github.com/thewhiteh4t/cve-2026-27483](https://github.com/thewhiteh4t/cve-2026-27483) :  ![starts](https://img.shields.io/github/stars/thewhiteh4t/cve-2026-27483.svg) ![forks](https://img.shields.io/github/forks/thewhiteh4t/cve-2026-27483.svg)

## CVE-2026-27470
 ZoneMinder is a free, open source closed-circuit television software application. In versions 1.36.37 and below and 1.37.61 through 1.38.0, there is a second-order SQL Injection vulnerability in the web/ajax/status.php file within the getNearEvents() function. Event field values (specifically Name and Cause) are stored safely via parameterized queries but are later retrieved and concatenated directly into SQL WHERE clauses without escaping. An authenticated user with Events edit and view permissions can exploit this to execute arbitrary SQL queries.



- [https://github.com/kocaemre/CVE-2026-27470](https://github.com/kocaemre/CVE-2026-27470) :  ![starts](https://img.shields.io/github/stars/kocaemre/CVE-2026-27470.svg) ![forks](https://img.shields.io/github/forks/kocaemre/CVE-2026-27470.svg)

- [https://github.com/d3vn0mi/CVE-2026-27470-POC](https://github.com/d3vn0mi/CVE-2026-27470-POC) :  ![starts](https://img.shields.io/github/stars/d3vn0mi/CVE-2026-27470-POC.svg) ![forks](https://img.shields.io/github/forks/d3vn0mi/CVE-2026-27470-POC.svg)

## CVE-2026-27199
 Werkzeug is a comprehensive WSGI web application library. Versions 3.1.5 and below, the safe_join function allows Windows device names as filenames if preceded by other path segments. This was previously reported as GHSA-hgf8-39gv-g3f2, but the added filtering failed to account for the fact that safe_join accepts paths with multiple segments, such as example/NUL. The function send_from_directory uses safe_join to safely serve files at user-specified paths under a directory. If the application is running on Windows, and the requested path ends with a special device name, the file will be opened successfully, but reading will hang indefinitely. This issue has been fixed in version 3.1.6.



- [https://github.com/alimezar/CVE-2026-27199-werkzeug-safe-join-bypass-PoC](https://github.com/alimezar/CVE-2026-27199-werkzeug-safe-join-bypass-PoC) :  ![starts](https://img.shields.io/github/stars/alimezar/CVE-2026-27199-werkzeug-safe-join-bypass-PoC.svg) ![forks](https://img.shields.io/github/forks/alimezar/CVE-2026-27199-werkzeug-safe-join-bypass-PoC.svg)

## CVE-2026-27180
 MajorDoMo (aka Major Domestic Module) is vulnerable to unauthenticated remote code execution through supply chain compromise via update URL poisoning. The saverestore module exposes its admin() method through the /objects/?module=saverestore endpoint without authentication because it uses gr('mode') (which reads directly from $_REQUEST) instead of the framework's $this-mode. An attacker can poison the system update URL via the auto_update_settings mode handler, then trigger the force_update handler to initiate the update chain. The autoUpdateSystem() method fetches an Atom feed from the attacker-controlled URL with trivial validation, downloads a tarball via curl with TLS verification disabled (CURLOPT_SSL_VERIFYPEER set to FALSE), extracts it using exec('tar xzvf ...'), and copies all extracted files to the document root using copyTree(). This allows an attacker to deploy arbitrary PHP files, including webshells, to the webroot with two GET requests.



- [https://github.com/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE](https://github.com/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-27180-MajorDoMo-unauthenticated-RCE.svg)

## CVE-2026-27179
 MajorDoMo (aka Major Domestic Module) contains an unauthenticated SQL injection vulnerability in the commands module. The commands_search.inc.php file directly interpolates the $_GET['parent'] parameter into multiple SQL queries without sanitization or parameterized queries. The commands module is loadable without authentication via the /objects/?module=commands endpoint, which includes arbitrary modules by name and calls their usual() method. Time-based blind SQL injection is exploitable using UNION SELECT SLEEP() syntax. Because MajorDoMo stores admin passwords as unsalted MD5 hashes in the users table, successful exploitation enables extraction of credentials and subsequent admin panel access.



- [https://github.com/p3Nt3st3r-sTAr/MajorDoMo-CVE-2026-27179](https://github.com/p3Nt3st3r-sTAr/MajorDoMo-CVE-2026-27179) :  ![starts](https://img.shields.io/github/stars/p3Nt3st3r-sTAr/MajorDoMo-CVE-2026-27179.svg) ![forks](https://img.shields.io/github/forks/p3Nt3st3r-sTAr/MajorDoMo-CVE-2026-27179.svg)

## CVE-2026-27174
 MajorDoMo (aka Major Domestic Module) allows unauthenticated remote code execution via the admin panel's PHP console feature. An include order bug in modules/panel.class.php causes execution to continue past a redirect() call that lacks an exit statement, allowing unauthenticated requests to reach the ajax handler in inc_panel_ajax.php. The console handler within that file passes user-supplied input from GET parameters (via register_globals) directly to eval() without any authentication check. An attacker can execute arbitrary PHP code by sending a crafted GET request to /admin.php with ajax_panel, op, and command parameters.



- [https://github.com/MaxMnMl/majordomo-CVE-2026-27174-poc](https://github.com/MaxMnMl/majordomo-CVE-2026-27174-poc) :  ![starts](https://img.shields.io/github/stars/MaxMnMl/majordomo-CVE-2026-27174-poc.svg) ![forks](https://img.shields.io/github/forks/MaxMnMl/majordomo-CVE-2026-27174-poc.svg)

## CVE-2026-26988
 LibreNMS is an auto-discovering PHP/MySQL/SNMP based network monitoring tool. Versions 25.12.0 and below contain an SQL Injection vulnerability in the ajax_table.php endpoint. The application fails to properly sanitize or parameterize user input when processing IPv6 address searches. Specifically, the address parameter is split into an address and a prefix, and the prefix portion is directly concatenated into the SQL query string without validation. This allows an attacker to inject arbitrary SQL commands, potentially leading to unauthorized data access or database manipulation. This issue has been fixed in version 26.2.0.



- [https://github.com/mbanyamer/CVE-2026-26988-LibreNMS-SQLi](https://github.com/mbanyamer/CVE-2026-26988-LibreNMS-SQLi) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26988-LibreNMS-SQLi.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26988-LibreNMS-SQLi.svg)

## CVE-2026-26980
 Ghost is a Node.js content management system. Versions 3.24.0 through 6.19.0 allow unauthenticated attackers to perform arbitrary reads from the database. This issue has been fixed in version 6.19.1.



- [https://github.com/dinosn/ghost-cve-2026-26980](https://github.com/dinosn/ghost-cve-2026-26980) :  ![starts](https://img.shields.io/github/stars/dinosn/ghost-cve-2026-26980.svg) ![forks](https://img.shields.io/github/forks/dinosn/ghost-cve-2026-26980.svg)

- [https://github.com/vognik/CVE-2026-26980](https://github.com/vognik/CVE-2026-26980) :  ![starts](https://img.shields.io/github/stars/vognik/CVE-2026-26980.svg) ![forks](https://img.shields.io/github/forks/vognik/CVE-2026-26980.svg)

## CVE-2026-26833
 thumbler through 1.1.2 allows OS command injection via the input, output, time, or size parameter in the thumbnail() function because user input is concatenated into a shell command string passed to child_process.exec() without proper sanitization or escaping.



- [https://github.com/zebbernCVE/npm-cve-2026-26830-26833](https://github.com/zebbernCVE/npm-cve-2026-26830-26833) :  ![starts](https://img.shields.io/github/stars/zebbernCVE/npm-cve-2026-26830-26833.svg) ![forks](https://img.shields.io/github/forks/zebbernCVE/npm-cve-2026-26830-26833.svg)

- [https://github.com/zebbernCVE/CVE-2026-26833](https://github.com/zebbernCVE/CVE-2026-26833) :  ![starts](https://img.shields.io/github/stars/zebbernCVE/CVE-2026-26833.svg) ![forks](https://img.shields.io/github/forks/zebbernCVE/CVE-2026-26833.svg)

## CVE-2026-26832
 node-tesseract-ocr is an npm package that provides a Node.js wrapper for Tesseract OCR. In all versions through 2.2.1, the recognize() function in src/index.js is vulnerable to OS Command Injection. The file path parameter is concatenated into a shell command string and passed to child_process.exec() without proper sanitization



- [https://github.com/zebbernCVE/CVE-2026-26832](https://github.com/zebbernCVE/CVE-2026-26832) :  ![starts](https://img.shields.io/github/stars/zebbernCVE/CVE-2026-26832.svg) ![forks](https://img.shields.io/github/forks/zebbernCVE/CVE-2026-26832.svg)

## CVE-2026-26831
 textract through 2.5.0 is vulnerable to OS Command Injection via the file path parameter in multiple extractors. When processing files with malicious filenames, the filePath is passed directly to child_process.exec() in lib/extractors/doc.js, rtf.js, dxf.js, images.js, and lib/util.js with inadequate sanitization



- [https://github.com/zebbernCVE/CVE-2026-26831](https://github.com/zebbernCVE/CVE-2026-26831) :  ![starts](https://img.shields.io/github/stars/zebbernCVE/CVE-2026-26831.svg) ![forks](https://img.shields.io/github/forks/zebbernCVE/CVE-2026-26831.svg)

## CVE-2026-26830
 pdf-image (npm package) through version 2.0.0 allows OS command injection via the pdfFilePath parameter. The constructGetInfoCommand and constructConvertCommandForPage functions use util.format() to interpolate user-controlled file paths into shell command strings that are executed via child_process.exec()



- [https://github.com/zebbernCVE/npm-cve-2026-26830-26833](https://github.com/zebbernCVE/npm-cve-2026-26830-26833) :  ![starts](https://img.shields.io/github/stars/zebbernCVE/npm-cve-2026-26830-26833.svg) ![forks](https://img.shields.io/github/forks/zebbernCVE/npm-cve-2026-26830-26833.svg)

- [https://github.com/zebbernCVE/CVE-2026-26830](https://github.com/zebbernCVE/CVE-2026-26830) :  ![starts](https://img.shields.io/github/stars/zebbernCVE/CVE-2026-26830.svg) ![forks](https://img.shields.io/github/forks/zebbernCVE/CVE-2026-26830.svg)

## CVE-2026-26801
 Server-Side Request Forgery (SSRF) vulnerability in pdfmake versions 0.3.0-beta.2 through 0.3.5 allows a remote attacker to obtain sensitive information via the src/URLResolver.js component. The fix was released in version 0.3.6 which introduces the setUrlAccessPolicy() method allowing server operators to define URL access rules. A warning is now logged when pdfmake is used server-side without a policy configured.



- [https://github.com/mariopepe/CVE-2026-26801-pdfmake-ssrf](https://github.com/mariopepe/CVE-2026-26801-pdfmake-ssrf) :  ![starts](https://img.shields.io/github/stars/mariopepe/CVE-2026-26801-pdfmake-ssrf.svg) ![forks](https://img.shields.io/github/forks/mariopepe/CVE-2026-26801-pdfmake-ssrf.svg)

## CVE-2026-26746
 OpenSourcePOS 3.4.1 contains a Local File Inclusion (LFI) vulnerability in the Sales.php::getInvoice() function. An attacker can read arbitrary files on the web server by manipulating the Invoice Type configuration. This issue can be chained with the file upload functionality to achieve Remote Code Execution (RCE).



- [https://github.com/hungnqdz/CVE-2026-26746](https://github.com/hungnqdz/CVE-2026-26746) :  ![starts](https://img.shields.io/github/stars/hungnqdz/CVE-2026-26746.svg) ![forks](https://img.shields.io/github/forks/hungnqdz/CVE-2026-26746.svg)

## CVE-2026-26744
 A user enumeration vulnerability exists in FormaLMS 4.1.18 and below in the password recovery functionality accessible via the /lostpwd endpoint. The application returns different error messages for valid and invalid usernames allowing an unauthenticated attacker to determine which usernames are registered in the system through observable response discrepancy.



- [https://github.com/lorenzobruno7/CVE-2026-26744](https://github.com/lorenzobruno7/CVE-2026-26744) :  ![starts](https://img.shields.io/github/stars/lorenzobruno7/CVE-2026-26744.svg) ![forks](https://img.shields.io/github/forks/lorenzobruno7/CVE-2026-26744.svg)

## CVE-2026-26720
 An issue in Twenty CRM v1.15.0 and before allows a remote attacker to execute arbitrary code via the local.driver.ts module.



- [https://github.com/dillonkirsch/CVE-2026-26720-Twenty-RCE](https://github.com/dillonkirsch/CVE-2026-26720-Twenty-RCE) :  ![starts](https://img.shields.io/github/stars/dillonkirsch/CVE-2026-26720-Twenty-RCE.svg) ![forks](https://img.shields.io/github/forks/dillonkirsch/CVE-2026-26720-Twenty-RCE.svg)

## CVE-2026-26717
 An issue in OpenFUN Richie (LMS) in src/richie/apps/courses/api.py. The application used the non-constant time == operator for HMAC signature verification in the sync_course_run_from_request function. This allows remote attackers to forge valid signatures and bypass authentication by measuring response time discrepancies



- [https://github.com/Rickidevs/CVE-2026-26717](https://github.com/Rickidevs/CVE-2026-26717) :  ![starts](https://img.shields.io/github/stars/Rickidevs/CVE-2026-26717.svg) ![forks](https://img.shields.io/github/forks/Rickidevs/CVE-2026-26717.svg)

## CVE-2026-26418
 Missing authentication and authorization in the web API of Tata Consultancy Services Cognix Recon Client v3.0 allows remote attackers to access application functionality without restriction via the network.



- [https://github.com/aksalsalimi/CVE-2026-26418](https://github.com/aksalsalimi/CVE-2026-26418) :  ![starts](https://img.shields.io/github/stars/aksalsalimi/CVE-2026-26418.svg) ![forks](https://img.shields.io/github/forks/aksalsalimi/CVE-2026-26418.svg)

## CVE-2026-26417
 A broken access control vulnerability in the password reset functionality of Tata Consultancy Services Cognix Recon Client v3.0 allows authenticated users to reset passwords of arbitrary user accounts via crafted requests.



- [https://github.com/aksalsalimi/CVE-2026-26417](https://github.com/aksalsalimi/CVE-2026-26417) :  ![starts](https://img.shields.io/github/stars/aksalsalimi/CVE-2026-26417.svg) ![forks](https://img.shields.io/github/forks/aksalsalimi/CVE-2026-26417.svg)

## CVE-2026-26416
 An authorization bypass vulnerability in Tata Consultancy Services Cognix Recon Client v3.0 allows authenticated users to escalate privileges across role boundaries via crafted requests.



- [https://github.com/aksalsalimi/CVE-2026-26416](https://github.com/aksalsalimi/CVE-2026-26416) :  ![starts](https://img.shields.io/github/stars/aksalsalimi/CVE-2026-26416.svg) ![forks](https://img.shields.io/github/forks/aksalsalimi/CVE-2026-26416.svg)

## CVE-2026-26399
 A stack-use-after-return issue exists in the Arduino_Core_STM32 library prior to version 1.7.0. The pwm_start() function allocates a TIM_HandleTypeDef structure on the stack and passes its address to HAL initialization routines, where it is stored in a global timer handle registry. After the function returns, interrupt service routines may dereference this dangling pointer, resulting in memory corruption.



- [https://github.com/Acen28/CVE-2026-26399-Disclosure](https://github.com/Acen28/CVE-2026-26399-Disclosure) :  ![starts](https://img.shields.io/github/stars/Acen28/CVE-2026-26399-Disclosure.svg) ![forks](https://img.shields.io/github/forks/Acen28/CVE-2026-26399-Disclosure.svg)

## CVE-2026-26336
 Hyland Alfresco allows unauthenticated attackers to read arbitrary files from protected directories (like WEB-INF) via the "/share/page/resource/" endpoint, thus leading to the disclosure of sensitive configuration files.



- [https://github.com/CEAarab/CVE-2026-26336-PoC](https://github.com/CEAarab/CVE-2026-26336-PoC) :  ![starts](https://img.shields.io/github/stars/CEAarab/CVE-2026-26336-PoC.svg) ![forks](https://img.shields.io/github/forks/CEAarab/CVE-2026-26336-PoC.svg)

## CVE-2026-26335
 Calero VeraSMART versions prior to 2022 R1 use static ASP.NET/IIS machineKey values configured for the VeraSMART web application and stored in C:\\Program Files (x86)\\Veramark\\VeraSMART\\WebRoot\\web.config. An attacker who obtains these keys can craft a valid ASP.NET ViewState payload that passes integrity validation and is accepted by the application, resulting in server-side deserialization and remote code execution in the context of the IIS application.



- [https://github.com/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE](https://github.com/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26335-Calero-VeraSMART-RCE.svg)

## CVE-2026-26331
 yt-dlp is a command-line audio/video downloader. Starting in version 2023.06.21 and prior to version 2026.02.21, when yt-dlp's `--netrc-cmd` command-line option (or `netrc_cmd` Python API parameter) is used, an attacker could achieve arbitrary command injection on the user's system with a maliciously crafted URL. yt-dlp maintainers assume the impact of this vulnerability to be high for anyone who uses `--netrc-cmd` in their command/configuration or `netrc_cmd` in their Python scripts. Even though the maliciously crafted URL itself will look very suspicious to many users, it would be trivial for a maliciously crafted webpage with an inconspicuous URL to covertly exploit this vulnerability via HTTP redirect. Users without `--netrc-cmd` in their arguments or `netrc_cmd` in their scripts are unaffected. No evidence has been found of this exploit being used in the wild. yt-dlp version 2026.02.21 fixes this issue by validating all netrc "machine" values and raising an error upon unexpected input. As a workaround, users who are unable to upgrade should avoid using the `--netrc-cmd` command-line option (or `netrc_cmd` Python API parameter), or they should at least not pass a placeholder (`{}`) in their `--netrc-cmd` argument.



- [https://github.com/dxlerYT/CVE-2026-26331](https://github.com/dxlerYT/CVE-2026-26331) :  ![starts](https://img.shields.io/github/stars/dxlerYT/CVE-2026-26331.svg) ![forks](https://img.shields.io/github/forks/dxlerYT/CVE-2026-26331.svg)

## CVE-2026-26268
 Cursor is a code editor built for programming with AI. Sandbox escape via writing .git configuration was possible in versions prior to 2.5. A malicious agent (ie prompt injection) could write to improperly protected .git settings, including git hooks, which may cause out-of-sandbox RCE next time they are triggered. No user interaction was required as Git executes these commands automatically. Fixed in version 2.5.



- [https://github.com/dhawaldesai/agentic-ioc-scanner](https://github.com/dhawaldesai/agentic-ioc-scanner) :  ![starts](https://img.shields.io/github/stars/dhawaldesai/agentic-ioc-scanner.svg) ![forks](https://img.shields.io/github/forks/dhawaldesai/agentic-ioc-scanner.svg)

## CVE-2026-26235
 JUNG Smart Visu Server 1.1.1050 contains a denial of service vulnerability that allows unauthenticated attackers to remotely shutdown or reboot the server. Attackers can send a single POST request to trigger the server reboot without requiring any authentication.



- [https://github.com/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown](https://github.com/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26235-JUNG-Smart-Visu-Server-Unauthenticated-Reboot-Shutdown.svg)

## CVE-2026-26221
 Hyland OnBase contains an unauthenticated .NET Remoting exposure in the OnBase Workflow Timer Service (Hyland.Core.Workflow.NTService.exe). An attacker who can reach the service can send crafted .NET Remoting requests to default HTTP channel endpoints on TCP/8900 (e.g., TimerServiceAPI.rem and TimerServiceEvents.rem for Workflow) to trigger unsafe object unmarshalling, enabling arbitrary file read/write. By writing attacker-controlled content into web-accessible locations or chaining with other OnBase features, this can lead to remote code execution. The same primitive can be abused by supplying a UNC path to coerce outbound NTLM authentication (SMB coercion) to an attacker-controlled host.



- [https://github.com/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE](https://github.com/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26221-Hyland-OnBase-Timer-Service-Unauthenticated-RCE.svg)

## CVE-2026-26215
 manga-image-translator version beta-0.3 and prior in shared API mode contains an unsafe deserialization vulnerability that can lead to unauthenticated remote code execution. The FastAPI endpoints /simple_execute/{method} and /execute/{method} deserialize attacker-controlled request bodies using pickle.loads() without validation. Although a nonce-based authorization check is intended to restrict access, the nonce defaults to an empty string and the check is skipped, allowing remote attackers to execute arbitrary code in the server context by sending a crafted pickle payload.



- [https://github.com/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE](https://github.com/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/-CVE-2026-26215-manga-image-translator-RCE.svg)

## CVE-2026-26198
 Ormar is a async mini ORM for Python. In versions 0.9.9 through 0.22.0, when performing aggregate queries, Ormar ORM constructs SQL expressions by passing user-supplied column names directly into `sqlalchemy.text()` without any validation or sanitization. The `min()` and `max()` methods in the `QuerySet` class accept arbitrary string input as the column parameter. While `sum()` and `avg()` are partially protected by an `is_numeric` type check that rejects non-existent fields, `min()` and `max()` skip this validation entirely. As a result, an attacker-controlled string is embedded as raw SQL inside the aggregate function call. Any unauthorized user can exploit this vulnerability to read the entire database contents, including tables unrelated to the queried model, by injecting a subquery as the column parameter. Version 0.23.0 contains a patch.



- [https://github.com/NetVanguard-cmd/CVE-2026-26198](https://github.com/NetVanguard-cmd/CVE-2026-26198) :  ![starts](https://img.shields.io/github/stars/NetVanguard-cmd/CVE-2026-26198.svg) ![forks](https://img.shields.io/github/forks/NetVanguard-cmd/CVE-2026-26198.svg)

- [https://github.com/sergicortesabadia/CVE-2026-26198-analysis](https://github.com/sergicortesabadia/CVE-2026-26198-analysis) :  ![starts](https://img.shields.io/github/stars/sergicortesabadia/CVE-2026-26198-analysis.svg) ![forks](https://img.shields.io/github/forks/sergicortesabadia/CVE-2026-26198-analysis.svg)

## CVE-2026-26128
 Improper authentication in Windows SMB Server allows an authorized attacker to elevate privileges locally.



- [https://github.com/jarnovandenbrink/CVE-2026-26128](https://github.com/jarnovandenbrink/CVE-2026-26128) :  ![starts](https://img.shields.io/github/stars/jarnovandenbrink/CVE-2026-26128.svg) ![forks](https://img.shields.io/github/forks/jarnovandenbrink/CVE-2026-26128.svg)

## CVE-2026-26118
 Server-side request forgery (ssrf) in Azure MCP Server allows an authorized attacker to elevate privileges over a network.



- [https://github.com/j-dahl7/mcp-attack-detection-sentinel](https://github.com/j-dahl7/mcp-attack-detection-sentinel) :  ![starts](https://img.shields.io/github/stars/j-dahl7/mcp-attack-detection-sentinel.svg) ![forks](https://img.shields.io/github/forks/j-dahl7/mcp-attack-detection-sentinel.svg)

## CVE-2026-26114
 Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a network.



- [https://github.com/huynambka/cve-2026-26114](https://github.com/huynambka/cve-2026-26114) :  ![starts](https://img.shields.io/github/stars/huynambka/cve-2026-26114.svg) ![forks](https://img.shields.io/github/forks/huynambka/cve-2026-26114.svg)

## CVE-2026-26030
 Semantic Kernel, Microsoft's semantic kernel Python SDK, has a remote code execution vulnerability in versions prior to 1.39.4, specifically within the `InMemoryVectorStore` filter functionality. The problem has been fixed in version `python-1.39.4`. Users should upgrade this version or higher. As a workaround, avoid using `InMemoryVectorStore` for production scenarios.



- [https://github.com/mbanyamer/CVE-2026-26030-Microsoft-Semantic-Kernel-1.39.4-RCE](https://github.com/mbanyamer/CVE-2026-26030-Microsoft-Semantic-Kernel-1.39.4-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-26030-Microsoft-Semantic-Kernel-1.39.4-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-26030-Microsoft-Semantic-Kernel-1.39.4-RCE.svg)

## CVE-2026-26026
 GLPI is a free asset and IT management software package. From 11.0.0 to before 11.0.6, template injection by an administrator lead to RCE. This vulnerability is fixed in 11.0.6.



- [https://github.com/CEAarab/CVE-2026-26026-PoC](https://github.com/CEAarab/CVE-2026-26026-PoC) :  ![starts](https://img.shields.io/github/stars/CEAarab/CVE-2026-26026-PoC.svg) ![forks](https://img.shields.io/github/forks/CEAarab/CVE-2026-26026-PoC.svg)

## CVE-2026-26012
 vaultwarden is an unofficial Bitwarden compatible server written in Rust, formerly known as bitwarden_rs. Prior to 1.35.3, a regular organization member can retrieve all ciphers within an organization, regardless of collection permissions. The endpoint /ciphers/organization-details is accessible to any organization member and internally uses Cipher::find_by_org to retrieve all ciphers. These ciphers are returned with CipherSyncType::Organization without enforcing collection-level access control. This vulnerability is fixed in 1.35.3.



- [https://github.com/Dulieno/CVE-2026-26012](https://github.com/Dulieno/CVE-2026-26012) :  ![starts](https://img.shields.io/github/stars/Dulieno/CVE-2026-26012.svg) ![forks](https://img.shields.io/github/forks/Dulieno/CVE-2026-26012.svg)

- [https://github.com/diegobaelen/CVE-2026-26012](https://github.com/diegobaelen/CVE-2026-26012) :  ![starts](https://img.shields.io/github/stars/diegobaelen/CVE-2026-26012.svg) ![forks](https://img.shields.io/github/forks/diegobaelen/CVE-2026-26012.svg)

## CVE-2026-25994
 PJSIP is a free and open source multimedia communication library written in C. In 2.16 and earlier, a buffer overflow vulnerability exists in PJNATH ICE Session when processing credentials with excessively long usernames.



- [https://github.com/VABISMO/cve-2026-25994_PJSIP](https://github.com/VABISMO/cve-2026-25994_PJSIP) :  ![starts](https://img.shields.io/github/stars/VABISMO/cve-2026-25994_PJSIP.svg) ![forks](https://img.shields.io/github/forks/VABISMO/cve-2026-25994_PJSIP.svg)

## CVE-2026-25991
 Tandoor Recipes is an application for managing recipes, planning meals, and building shopping lists. Prior to 2.5.1, there is a Blind Server-Side Request Forgery (SSRF) vulnerability in the Cookmate recipe import feature of Tandoor Recipes. The application fails to validate the destination URL after following HTTP redirects, allowing any authenticated user (including standard users without administrative privileges) to force the server to connect to arbitrary internal or external resources. The vulnerability lies in cookbook/integration/cookmate.py, within the Cookmate integration class. This vulnerability can be leveraged to scan internal network ports, access cloud instance metadata (e.g., AWS/GCP Metadata Service), or disclose the server's real IP address. This vulnerability is fixed in 2.5.1.



- [https://github.com/drkim-dev/CVE-2026-25991](https://github.com/drkim-dev/CVE-2026-25991) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-25991.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-25991.svg)

## CVE-2026-25964
 Tandoor Recipes is an application for managing recipes, planning meals, and building shopping lists. Prior to 2.5.1, a Path Traversal vulnerability in the RecipeImport workflow of Tandoor Recipes allows authenticated users with import permissions to read arbitrary files on the server. This vulnerability stems from a lack of input validation in the file_path parameter and insufficient checks in the Local storage backend, enabling an attacker to bypass storage directory restrictions and access sensitive system files (e.g., /etc/passwd) or application configuration files (e.g., settings.py), potentially leading to full system compromise. This vulnerability is fixed in 2.5.1.



- [https://github.com/drkim-dev/CVE-2026-25964](https://github.com/drkim-dev/CVE-2026-25964) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-25964.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-25964.svg)

## CVE-2026-25961
 SumatraPDF is a multi-format reader for Windows. In 3.5.0 through 3.5.2, SumatraPDF's update mechanism disables TLS hostname verification (INTERNET_FLAG_IGNORE_CERT_CN_INVALID) and executes installers without signature checks. A network attacker with any valid TLS certificate (e.g., Let's Encrypt) can intercept the update check request, inject a malicious installer URL, and achieve arbitrary code execution.



- [https://github.com/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE](https://github.com/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25961-SumatraPDF-3.5.0---3.5.2-RCE.svg)

## CVE-2026-25940
 jsPDF is a library to generate PDFs in JavaScript. Prior to 4.2.0, user control of properties and methods of the Acroform module allows users to inject arbitrary PDF objects, such as JavaScript actions. If given the possibility to pass unsanitized input to one of the following property, a user can inject arbitrary PDF objects, such as JavaScript actions, which are executed when the victim hovers over the radio option. The vulnerability has been fixed in jsPDF@4.2.0. As a workaround, sanitize user input before passing it to the vulnerable API members.



- [https://github.com/dajneem23/CVE-2026-25940](https://github.com/dajneem23/CVE-2026-25940) :  ![starts](https://img.shields.io/github/stars/dajneem23/CVE-2026-25940.svg) ![forks](https://img.shields.io/github/forks/dajneem23/CVE-2026-25940.svg)

## CVE-2026-25939
 FUXA is a web-based Process Visualization (SCADA/HMI/Dashboard) software. From 1.2.8 through version 1.2.10, 
an authorization bypass vulnerability in the FUXA allows an unauthenticated, remote attacker to create and modify arbitrary schedulers, exposing connected ICS/SCADA environments to follow-on actions. This has been patched in FUXA version 1.2.11.



- [https://github.com/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary](https://github.com/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25939-SCADA-FUXA-Unauthenticated-Remote-Arbitrary.svg)

## CVE-2026-25924
 Kanboard is project management software focused on Kanban methodology. Prior to 1.2.50, a security control bypass vulnerability in Kanboard allows an authenticated administrator to achieve full Remote Code Execution (RCE). Although the application correctly hides the plugin installation interface when the PLUGIN_INSTALLER configuration is set to false, the underlying backend endpoint fails to verify this security setting. An attacker can exploit this oversight to force the server to download and install a malicious plugin, leading to arbitrary code execution. This vulnerability is fixed in 1.2.50.



- [https://github.com/drkim-dev/CVE-2026-25924](https://github.com/drkim-dev/CVE-2026-25924) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-25924.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-25924.svg)

## CVE-2026-25916
 Roundcube Webmail before 1.5.13 and 1.6 before 1.6.13, when "Block remote images" is used, does not block SVG feImage.



- [https://github.com/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute](https://github.com/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25916-Roundcube-Webmail-DOM-based-XSS-Exploit-via-SVG-href-Attribute.svg)

## CVE-2026-25895
 FUXA is a web-based Process Visualization (SCADA/HMI/Dashboard) software. A path traversal vulnerability in FUXA allows an unauthenticated, remote attacker to write arbitrary files to arbitrary locations on the server filesystem. This affects FUXA through version 1.2.9. This issue has been patched in FUXA version 1.2.10.



- [https://github.com/Hann1bl3L3ct3r/FUXAPWN](https://github.com/Hann1bl3L3ct3r/FUXAPWN) :  ![starts](https://img.shields.io/github/stars/Hann1bl3L3ct3r/FUXAPWN.svg) ![forks](https://img.shields.io/github/forks/Hann1bl3L3ct3r/FUXAPWN.svg)

## CVE-2026-25892
 Adminer is open-source database management software. Adminer v5.4.1 and earlier has a version check mechanism where adminer.org sends signed version info via JavaScript postMessage, which the browser then POSTs to ?script=version. This endpoint lacks origin validation and accepts POST data from any source. An attacker can POST version[] parameter which PHP converts to an array. On next page load, openssl_verify() receives this array instead of string and throws TypeError, returning HTTP 500 to all users. Upgrade to Adminer 5.4.2.



- [https://github.com/dzmind2312/CVE_2026_25892](https://github.com/dzmind2312/CVE_2026_25892) :  ![starts](https://img.shields.io/github/stars/dzmind2312/CVE_2026_25892.svg) ![forks](https://img.shields.io/github/forks/dzmind2312/CVE_2026_25892.svg)

## CVE-2026-25890
 File Browser provides a file managing interface within a specified directory and it can be used to upload, delete, preview, rename and edit files. Prior to 2.57.1, an authenticated user can bypass the application's "Disallow" file path rules by modifying the request URL. By adding multiple slashes (e.g., //private/) to the path, the authorization check fails to match the rule, while the underlying filesystem resolves the path correctly, granting unauthorized access to restricted files. This vulnerability is fixed in 2.57.1.



- [https://github.com/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass](https://github.com/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25890-FileBrowser-Access-Control-Bypass.svg)

## CVE-2026-25854
 Occasional URL redirection to untrusted Site ('Open Redirect') vulnerability in Apache Tomcat via the LoadBalancerDrainingValve.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.18, from 10.1.0-M1 through 10.1.52, from 9.0.0.M23 through 9.0.115, from 8.5.30 through 8.5.100.
Other, unsupported versions may also be affected

Users are recommended to upgrade to version 11.0.20, 10.1.53 or 9.0.116, which fix the issue.



- [https://github.com/gregk4sec/cve-2026-25854](https://github.com/gregk4sec/cve-2026-25854) :  ![starts](https://img.shields.io/github/stars/gregk4sec/cve-2026-25854.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/cve-2026-25854.svg)

## CVE-2026-25807
 ZAI Shell is an autonomous SysOps agent designed to navigate, repair, and secure complex environments. Prior to 9.0.3, the P2P terminal sharing feature (share start) opens a TCP socket on port 5757 without any authentication mechanism. Any remote attacker can connect to this port using a simple socket script. An attacker who connects to a ZAI-Shell P2P session running in --no-ai mode can send arbitrary system commands. If the host user approves the command without reviewing its contents, the command executes directly with the user's privileges, bypassing all Sentinel safety checks. This vulnerability is fixed in 9.0.3.



- [https://github.com/ibrahmsql/CVE-2026-25807-Exploit](https://github.com/ibrahmsql/CVE-2026-25807-Exploit) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2026-25807-Exploit.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2026-25807-Exploit.svg)

## CVE-2026-25770
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 3.9.0 and prior to version 4.14.3, a privilege escalation vulnerability exists in the Wazuh Manager's cluster synchronization protocol. The `wazuh-clusterd` service allows authenticated nodes to write arbitrary files to the manager’s file system with the permissions of the `wazuh` system user. Due to insecure default permissions, the `wazuh` user has write access to the manager's main configuration file (`/var/ossec/etc/ossec.conf`). By leveraging the cluster protocol to overwrite `ossec.conf`, an attacker can inject a malicious `localfile` command block. The `wazuh-logcollector` service, which runs as root, parses this configuration and executes the injected command. This chain allows an attacker with cluster credentials to gain full Root Remote Code Execution, violating the principle of least privilege and bypassing the intended security model. Version 4.14.3 fixes the issue.



- [https://github.com/Samres27/CVE-2026-25769---CVE-2026-25770](https://github.com/Samres27/CVE-2026-25769---CVE-2026-25770) :  ![starts](https://img.shields.io/github/stars/Samres27/CVE-2026-25769---CVE-2026-25770.svg) ![forks](https://img.shields.io/github/forks/Samres27/CVE-2026-25769---CVE-2026-25770.svg)

## CVE-2026-25769
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Versions 4.0.0 through 4.14.2 have a Remote Code Execution (RCE) vulnerability due to Deserialization of Untrusted Data). All Wazuh deployments using cluster mode (master/worker architecture) and any organization with a compromised worker node (e.g., through initial access, insider threat, or supply chain attack) are impacted. An attacker who gains access to a worker node (through any means) can achieve full RCE on the master node with root privileges. Version 4.14.3 fixes the issue.



- [https://github.com/hakaioffsec/CVE-2026-25769](https://github.com/hakaioffsec/CVE-2026-25769) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/CVE-2026-25769.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/CVE-2026-25769.svg)

- [https://github.com/0xBlackash/CVE-2026-25769](https://github.com/0xBlackash/CVE-2026-25769) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-25769.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-25769.svg)

- [https://github.com/njeru-codes/CVE-2026-25769](https://github.com/njeru-codes/CVE-2026-25769) :  ![starts](https://img.shields.io/github/stars/njeru-codes/CVE-2026-25769.svg) ![forks](https://img.shields.io/github/forks/njeru-codes/CVE-2026-25769.svg)

- [https://github.com/Samres27/CVE-2026-25769---CVE-2026-25770](https://github.com/Samres27/CVE-2026-25769---CVE-2026-25770) :  ![starts](https://img.shields.io/github/stars/Samres27/CVE-2026-25769---CVE-2026-25770.svg) ![forks](https://img.shields.io/github/forks/Samres27/CVE-2026-25769---CVE-2026-25770.svg)

## CVE-2026-25755
 jsPDF is a library to generate PDFs in JavaScript. Prior to 4.2.0, user control of the argument of the `addJS` method allows an attacker to inject arbitrary PDF objects into the generated document. By crafting a payload that escapes the JavaScript string delimiter, an attacker can execute malicious actions or alter the document structure, impacting any user who opens the generated PDF. The vulnerability has been fixed in jspdf@4.2.0. As a workaround, escape parentheses in user-provided JavaScript code before passing them to the `addJS` method.



- [https://github.com/absholi7ly/jsPDF-Object-Injection](https://github.com/absholi7ly/jsPDF-Object-Injection) :  ![starts](https://img.shields.io/github/stars/absholi7ly/jsPDF-Object-Injection.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/jsPDF-Object-Injection.svg)

## CVE-2026-25747
 Deserialization of Untrusted Data vulnerability in Apache Camel LevelDB component.

The Camel-LevelDB DefaultLevelDBSerializer class deserializes data read from the LevelDB aggregation repository using java.io.ObjectInputStream without applying any ObjectInputFilter or class-loading restrictions. An attacker who can write to the LevelDB database files used by a Camel application can inject a crafted serialized Java object that, when deserialized during normal aggregation repository operations, results in arbitrary code execution in the context of the application.
This issue affects Apache Camel: from 4.10.0 before 4.10.8, from 4.14.0 before 4.14.5, from 4.15.0 before 4.18.0.

Users are recommended to upgrade to version 4.18.0, which fixes the issue. For the 4.10.x LTS releases, users are recommended to upgrade to 4.10.9, while for 4.14.x LTS releases, users are recommended to upgrade to 4.14.5



- [https://github.com/oscerd/CVE-2026-25747](https://github.com/oscerd/CVE-2026-25747) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-25747.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-25747.svg)

## CVE-2026-25746
 OpenEMR is a free and open source electronic health records and medical practice management application. Versions prior to 8.0.0 contain a SQL injection vulnerability in prescription that can be exploited by authenticated attackers. The vulnerability exists due to insufficient input validation in the prescription listing functionality. Version 8.0.0 fixes the vulnerability.



- [https://github.com/ChrisSub08/CVE-2026-25746_SqlInjectionVulnerabilityOpenEMR7.0.4](https://github.com/ChrisSub08/CVE-2026-25746_SqlInjectionVulnerabilityOpenEMR7.0.4) :  ![starts](https://img.shields.io/github/stars/ChrisSub08/CVE-2026-25746_SqlInjectionVulnerabilityOpenEMR7.0.4.svg) ![forks](https://img.shields.io/github/forks/ChrisSub08/CVE-2026-25746_SqlInjectionVulnerabilityOpenEMR7.0.4.svg)

## CVE-2026-25732
 NiceGUI is a Python-based UI framework. Prior to 3.7.0, NiceGUI's FileUpload.name property exposes client-supplied filename metadata without sanitization, enabling path traversal when developers use the pattern UPLOAD_DIR / file.name. Malicious filenames containing ../ sequences allow attackers to write files outside intended directories, with potential for remote code execution through application file overwrites in vulnerable deployment patterns. This design creates a prevalent security footgun affecting applications following common community patterns. Note: Exploitation requires application code incorporating file.name into filesystem paths without sanitization. Applications using fixed paths, generated filenames, or explicit sanitization are not affected. This vulnerability is fixed in 3.7.0.



- [https://github.com/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1](https://github.com/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25732-NiceGUI-3.6.1.svg)

## CVE-2026-25731
 calibre is an e-book manager. Prior to 9.2.0, a Server-Side Template Injection (SSTI) vulnerability in Calibre's Templite templating engine allows arbitrary code execution when a user converts an ebook using a malicious custom template file via the --template-html or --template-html-index command-line options. This vulnerability is fixed in 9.2.0.



- [https://github.com/dxlerYT/CVE-2026-25731](https://github.com/dxlerYT/CVE-2026-25731) :  ![starts](https://img.shields.io/github/stars/dxlerYT/CVE-2026-25731.svg) ![forks](https://img.shields.io/github/forks/dxlerYT/CVE-2026-25731.svg)

## CVE-2026-25676
 The installer of M-Track Duo HD version 1.0.0 contains an issue with the DLL search path, which may lead to insecurely loading Dynamic Link Libraries. As a result, arbitrary code may be executed with administrator privileges.



- [https://github.com/Nexxus67/cve-2026-25676](https://github.com/Nexxus67/cve-2026-25676) :  ![starts](https://img.shields.io/github/stars/Nexxus67/cve-2026-25676.svg) ![forks](https://img.shields.io/github/forks/Nexxus67/cve-2026-25676.svg)

## CVE-2026-25643
 Frigate is a network video recorder (NVR) with realtime local object detection for IP cameras. Prior to 0.16.4, a critical Remote Command Execution (RCE) vulnerability has been identified in the Frigate integration with go2rtc. The application does not sanitize user input in the video stream configuration (config.yaml), allowing direct injection of system commands via the exec: directive. The go2rtc service executes these commands without restrictions. This vulnerability is only exploitable by an administrator or users who have exposed their Frigate install to the open internet with no authentication which allows anyone full administrative control. This vulnerability is fixed in 0.16.4.



- [https://github.com/joshuavanderpoll/CVE-2026-25643](https://github.com/joshuavanderpoll/CVE-2026-25643) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2026-25643.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2026-25643.svg)

- [https://github.com/jduardo2704/CVE-2026-25643-Frigate-RCE](https://github.com/jduardo2704/CVE-2026-25643-Frigate-RCE) :  ![starts](https://img.shields.io/github/stars/jduardo2704/CVE-2026-25643-Frigate-RCE.svg) ![forks](https://img.shields.io/github/forks/jduardo2704/CVE-2026-25643-Frigate-RCE.svg)

- [https://github.com/DyniePro/CVE-2026-25643](https://github.com/DyniePro/CVE-2026-25643) :  ![starts](https://img.shields.io/github/stars/DyniePro/CVE-2026-25643.svg) ![forks](https://img.shields.io/github/forks/DyniePro/CVE-2026-25643.svg)

## CVE-2026-25604
 In AWS Auth manager, the origin of the SAML authentication has been used as provided by the client and not verified against the actual instance URL. 
This allowed to gain access to different instances with potentially different access controls by reusing SAML response from other instances.

You should upgrade to 9.22.0 version of provider if you use AWS Auth Manager.



- [https://github.com/John-Jung/CVE-2026-25604-PoC](https://github.com/John-Jung/CVE-2026-25604-PoC) :  ![starts](https://img.shields.io/github/stars/John-Jung/CVE-2026-25604-PoC.svg) ![forks](https://img.shields.io/github/forks/John-Jung/CVE-2026-25604-PoC.svg)

## CVE-2026-25596
 InvoicePlane is a self-hosted open source application for managing invoices, clients, and payments. A Stored Cross-Site Scripting (XSS) vulnerability exists in InvoicePlane 1.7.0 via the Product Unit Name fields. An authenticated administrator can inject malicious JavaScript that executes when any administrator views an invoice containing a product with the malicious unit. Version 1.7.1 patches the issue.



- [https://github.com/lagathos/CVE-2026-25596](https://github.com/lagathos/CVE-2026-25596) :  ![starts](https://img.shields.io/github/stars/lagathos/CVE-2026-25596.svg) ![forks](https://img.shields.io/github/forks/lagathos/CVE-2026-25596.svg)

## CVE-2026-25595
 InvoicePlane is a self-hosted open source application for managing invoices, clients, and payments. A Stored Cross-Site Scripting (XSS) vulnerability exists in InvoicePlane 1.7.0 via the Invoice Number field. An authenticated administrator can inject malicious JavaScript that executes when any administrator views the affected invoice or visits the dashboard. Version 1.7.1 patches the issue.



- [https://github.com/lagathos/CVE-2026-25595](https://github.com/lagathos/CVE-2026-25595) :  ![starts](https://img.shields.io/github/stars/lagathos/CVE-2026-25595.svg) ![forks](https://img.shields.io/github/forks/lagathos/CVE-2026-25595.svg)

## CVE-2026-25594
 InvoicePlane is a self-hosted open source application for managing invoices, clients, and payments. A Stored Cross-Site Scripting (XSS) vulnerability exists in InvoicePlane 1.7.0 via the Family Name field. The `family_name` value is rendered without HTML encoding inside the family dropdown on the product form. When an administrator creates a family with a malicious name, the payload executes in the browser of any administrator who visits the product form. Version 1.7.1 patches the issue.



- [https://github.com/lagathos/CVE-2026-25594](https://github.com/lagathos/CVE-2026-25594) :  ![starts](https://img.shields.io/github/stars/lagathos/CVE-2026-25594.svg) ![forks](https://img.shields.io/github/forks/lagathos/CVE-2026-25594.svg)

## CVE-2026-25589
 RedisBloom is a probabilistic data structures module for Redis. In all versions of RedisBloom before 2.8.20, the module does not properly validate serialized values processed through the Redis RESTORE command. An authenticated attacker with permission to execute RESTORE on a server with the RedisBloom module loaded can supply a crafted serialized payload that triggers invalid memory access and may lead to remote code execution. A workaround is to restrict access to the RESTORE command with ACL rules. This issue is fixed in version 2.8.20.



- [https://github.com/mgiay/CVE-2026-25589-25588-25243-23631-23479-REDIS](https://github.com/mgiay/CVE-2026-25589-25588-25243-23631-23479-REDIS) :  ![starts](https://img.shields.io/github/stars/mgiay/CVE-2026-25589-25588-25243-23631-23479-REDIS.svg) ![forks](https://img.shields.io/github/forks/mgiay/CVE-2026-25589-25588-25243-23631-23479-REDIS.svg)

## CVE-2026-25548
 InvoicePlane is a self-hosted open source application for managing invoices, clients, and payments. A critical Remote Code Execution (RCE) vulnerability exists in InvoicePlane 1.7.0 through a chained Local File Inclusion (LFI) and Log Poisoning attack. An authenticated administrator can execute arbitrary system commands on the server by manipulating the `public_invoice_template` setting to include poisoned log files containing PHP code. Version 1.7.1 patches the issue.



- [https://github.com/lagathos/CVE-2026-25548](https://github.com/lagathos/CVE-2026-25548) :  ![starts](https://img.shields.io/github/stars/lagathos/CVE-2026-25548.svg) ![forks](https://img.shields.io/github/forks/lagathos/CVE-2026-25548.svg)

## CVE-2026-25546
 Godot MCP is a Model Context Protocol (MCP) server for interacting with the Godot game engine. Prior to version 0.1.1, a command injection vulnerability in godot-mcp allows remote code execution. The executeOperation function passed user-controlled input (e.g., projectPath) directly to exec(), which spawns a shell. An attacker could inject shell metacharacters like $(command) or &calc to execute arbitrary commands with the privileges of the MCP server process. This affects any tool that accepts projectPath, including create_scene, add_node, load_sprite, and others. This issue has been patched in version 0.1.1.



- [https://github.com/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection](https://github.com/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25546-godot-mcp-0.1.1-OS-Command-Injection.svg)

## CVE-2026-25526
 JinJava is a Java-based template engine based on django template syntax, adapted to render jinja templates. Prior to versions 2.7.6 and 2.8.3, JinJava is vulnerable to arbitrary Java execution via bypass through ForTag. This allows arbitrary Java class instantiation and file access bypassing built-in sandbox restrictions. This issue has been patched in versions 2.7.6 and 2.8.3.



- [https://github.com/av4nth1ka/jinjava-cve-2026-25526-poc](https://github.com/av4nth1ka/jinjava-cve-2026-25526-poc) :  ![starts](https://img.shields.io/github/stars/av4nth1ka/jinjava-cve-2026-25526-poc.svg) ![forks](https://img.shields.io/github/forks/av4nth1ka/jinjava-cve-2026-25526-poc.svg)

## CVE-2026-25514
 FacturaScripts is open-source enterprise resource planning and accounting software. Prior to version 2025.81, FacturaScripts contains a critical SQL injection vulnerability in the autocomplete functionality that allows authenticated attackers to extract sensitive data from the database including user credentials, configuration settings, and all stored business data. The vulnerability exists in the CodeModel::all() method where user-supplied parameters are directly concatenated into SQL queries without sanitization or parameterized binding. This issue has been patched in version 2025.81.



- [https://github.com/lukasz-rybak/CVE-2026-25514](https://github.com/lukasz-rybak/CVE-2026-25514) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-25514.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-25514.svg)

## CVE-2026-25513
 FacturaScripts is open-source enterprise resource planning and accounting software. Prior to version 2025.81, FacturaScripts contains a critical SQL injection vulnerability in the REST API that allows authenticated API users to execute arbitrary SQL queries through the sort parameter. The vulnerability exists in the ModelClass::getOrderBy() method where user-supplied sorting parameters are directly concatenated into the SQL ORDER BY clause without validation or sanitization. This affects all API endpoints that support sorting functionality. This issue has been patched in version 2025.81.



- [https://github.com/lukasz-rybak/CVE-2026-25513](https://github.com/lukasz-rybak/CVE-2026-25513) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-25513.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-25513.svg)

## CVE-2026-25512
 Group-Office is an enterprise customer relationship management and groupware tool. Prior to versions 6.8.150, 25.0.82, and 26.0.5, there is a remote code execution (RCE) vulnerability in Group-Office. The endpoint email/message/tnefAttachmentFromTempFile directly concatenates the user-controlled parameter tmp_file into an exec() call. By injecting shell metacharacters into tmp_file, an authenticated attacker can execute arbitrary system commands on the server. This issue has been patched in versions 6.8.150, 25.0.82, and 26.0.5.



- [https://github.com/NumberOreo1/CVE-2026-25512](https://github.com/NumberOreo1/CVE-2026-25512) :  ![starts](https://img.shields.io/github/stars/NumberOreo1/CVE-2026-25512.svg) ![forks](https://img.shields.io/github/forks/NumberOreo1/CVE-2026-25512.svg)

- [https://github.com/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE](https://github.com/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25512-PoC-Group-Office-Authenticated-RCE.svg)

## CVE-2026-25253
 OpenClaw (aka clawdbot or Moltbot) before 2026.1.29 obtains a gatewayUrl value from a query string and automatically makes a WebSocket connection without prompting, sending a token value.



- [https://github.com/ethiack/moltbot-1click-rce](https://github.com/ethiack/moltbot-1click-rce) :  ![starts](https://img.shields.io/github/stars/ethiack/moltbot-1click-rce.svg) ![forks](https://img.shields.io/github/forks/ethiack/moltbot-1click-rce.svg)

- [https://github.com/adibirzu/openclaw-security-monitor](https://github.com/adibirzu/openclaw-security-monitor) :  ![starts](https://img.shields.io/github/stars/adibirzu/openclaw-security-monitor.svg) ![forks](https://img.shields.io/github/forks/adibirzu/openclaw-security-monitor.svg)

- [https://github.com/al4n4n/CVE-2026-25253-research](https://github.com/al4n4n/CVE-2026-25253-research) :  ![starts](https://img.shields.io/github/stars/al4n4n/CVE-2026-25253-research.svg) ![forks](https://img.shields.io/github/forks/al4n4n/CVE-2026-25253-research.svg)

- [https://github.com/EQSTLab/CVE-2026-25253](https://github.com/EQSTLab/CVE-2026-25253) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-25253.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-25253.svg)

- [https://github.com/FrigateCaptain/openclaw_vulnerabilities_and_solutions](https://github.com/FrigateCaptain/openclaw_vulnerabilities_and_solutions) :  ![starts](https://img.shields.io/github/stars/FrigateCaptain/openclaw_vulnerabilities_and_solutions.svg) ![forks](https://img.shields.io/github/forks/FrigateCaptain/openclaw_vulnerabilities_and_solutions.svg)

- [https://github.com/KajzingerAkos/CVE-2026-25253](https://github.com/KajzingerAkos/CVE-2026-25253) :  ![starts](https://img.shields.io/github/stars/KajzingerAkos/CVE-2026-25253.svg) ![forks](https://img.shields.io/github/forks/KajzingerAkos/CVE-2026-25253.svg)

- [https://github.com/Joseph19820124/openclaw-vuln-report](https://github.com/Joseph19820124/openclaw-vuln-report) :  ![starts](https://img.shields.io/github/stars/Joseph19820124/openclaw-vuln-report.svg) ![forks](https://img.shields.io/github/forks/Joseph19820124/openclaw-vuln-report.svg)

- [https://github.com/Ckokoski/moatbot-security](https://github.com/Ckokoski/moatbot-security) :  ![starts](https://img.shields.io/github/stars/Ckokoski/moatbot-security.svg) ![forks](https://img.shields.io/github/forks/Ckokoski/moatbot-security.svg)

- [https://github.com/ZhaoymOvO/openclaw-1click-rce-env](https://github.com/ZhaoymOvO/openclaw-1click-rce-env) :  ![starts](https://img.shields.io/github/stars/ZhaoymOvO/openclaw-1click-rce-env.svg) ![forks](https://img.shields.io/github/forks/ZhaoymOvO/openclaw-1click-rce-env.svg)

- [https://github.com/msaleme/start-here](https://github.com/msaleme/start-here) :  ![starts](https://img.shields.io/github/stars/msaleme/start-here.svg) ![forks](https://img.shields.io/github/forks/msaleme/start-here.svg)

- [https://github.com/siyad01/agentbox](https://github.com/siyad01/agentbox) :  ![starts](https://img.shields.io/github/stars/siyad01/agentbox.svg) ![forks](https://img.shields.io/github/forks/siyad01/agentbox.svg)

- [https://github.com/Cyber-Warrior-Network/trust-gate-mcp](https://github.com/Cyber-Warrior-Network/trust-gate-mcp) :  ![starts](https://img.shields.io/github/stars/Cyber-Warrior-Network/trust-gate-mcp.svg) ![forks](https://img.shields.io/github/forks/Cyber-Warrior-Network/trust-gate-mcp.svg)

## CVE-2026-25242
 Gogs is an open source self-hosted Git service. Versions 0.13.4 and below expose unauthenticated file upload endpoints by default. When the global RequireSigninView setting is disabled (default), any remote user can upload arbitrary files to the server via /releases/attachments and /issues/attachments. This enables the instance to be abused as a public file host, potentially leading to disk exhaustion, content hosting, or delivery of malware. CSRF tokens do not mitigate this attack due to same-origin cookie issuance. This issue has been fixed in version 0.14.1.



- [https://github.com/mindkernel/CVE-2026-25242](https://github.com/mindkernel/CVE-2026-25242) :  ![starts](https://img.shields.io/github/stars/mindkernel/CVE-2026-25242.svg) ![forks](https://img.shields.io/github/forks/mindkernel/CVE-2026-25242.svg)

## CVE-2026-25232
 Gogs is an open source self-hosted Git service. Versions 0.13.4 and below have an access control bypass vulnerability which allows any repository collaborator with Write permissions to delete protected branches (including the default branch) by sending a direct POST request, completely bypassing the branch protection mechanism. This vulnerability in the DeleteBranchPost function eenables privilege escalation from Write to Admin level, allowing low-privilege users to perform dangerous operations that should be restricted to administrators only. Although Git Hook layer correctly prevents protected branch deletion via SSH push, the web interface deletion operation does not trigger Git Hooks, resulting in complete bypass of protection mechanisms. In oder to exploit this vulnerability, attackers must have write permissions to the target repository, protected branches configured to the target repository and access to the Gogs web interface. This issue has been fixed in version 0.14.1.



- [https://github.com/H1sok444/CVE-2026-25232-PoC](https://github.com/H1sok444/CVE-2026-25232-PoC) :  ![starts](https://img.shields.io/github/stars/H1sok444/CVE-2026-25232-PoC.svg) ![forks](https://img.shields.io/github/forks/H1sok444/CVE-2026-25232-PoC.svg)

## CVE-2026-25211
 Llama Stack (aka llama-stack) before 0.4.0rc3 does not censor the pgvector password in the initialization log.



- [https://github.com/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211](https://github.com/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211) :  ![starts](https://img.shields.io/github/stars/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211.svg)

## CVE-2026-25197
 A specific endpoint allows authenticated users to pivot to other user profiles by modifying the id number in the API call.



- [https://github.com/MichaelAdamGroberman/CVE-2026-25197](https://github.com/MichaelAdamGroberman/CVE-2026-25197) :  ![starts](https://img.shields.io/github/stars/MichaelAdamGroberman/CVE-2026-25197.svg) ![forks](https://img.shields.io/github/forks/MichaelAdamGroberman/CVE-2026-25197.svg)

## CVE-2026-25177
 Improper restriction of names for files and other resources in Active Directory Domain Services allows an authorized attacker to elevate privileges over a network.



- [https://github.com/danaug23/detect_CVE-2026-25177](https://github.com/danaug23/detect_CVE-2026-25177) :  ![starts](https://img.shields.io/github/stars/danaug23/detect_CVE-2026-25177.svg) ![forks](https://img.shields.io/github/forks/danaug23/detect_CVE-2026-25177.svg)

## CVE-2026-25130
 Cybersecurity AI (CAI) is a framework for AI Security. In versions up to and including 0.5.10, the CAI (Cybersecurity AI) framework contains multiple argument injection vulnerabilities in its function tools. User-controlled input is passed directly to shell commands via `subprocess.Popen()` with `shell=True`, allowing attackers to execute arbitrary commands on the host system. The `find_file()` tool executes without requiring user approval because find is considered a "safe" pre-approved command. This means an attacker can achieve Remote Code Execution (RCE) by injecting malicious arguments (like -exec) into the args parameter, completely bypassing any human-in-the-loop safety mechanisms. Commit e22a1220f764e2d7cf9da6d6144926f53ca01cde contains a fix.



- [https://github.com/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10](https://github.com/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-25130-Cybersecurity-AI-CAI-Framework-0.5.10.svg)

## CVE-2026-25126
 PolarLearn is a free and open-source learning program. Prior to version 0-PRERELEASE-15, the vote API route (`POST /api/v1/forum/vote`) trusts the JSON body’s `direction` value without runtime validation. TypeScript types are not enforced at runtime, so an attacker can send arbitrary strings (e.g., `"x"`) as `direction`. Downstream (`VoteServer`) treats any non-`"up"` and non-`null` value as a downvote and persists the invalid value in `votes_data`. This can be exploited to bypass intended business logic. Version 0-PRERELEASE-15 fixes the vulnerability.



- [https://github.com/Jvr2022/CVE-2026-25126](https://github.com/Jvr2022/CVE-2026-25126) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-25126.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-25126.svg)

## CVE-2026-25099
 Bludit’s API plugin allows an authenticated attacker with a valid API token to upload files of any type and extension without restriction, which can then be executed, leading to Remote Code Execution.

This issue was fixed in 3.18.4.



- [https://github.com/yahiahamza/CVE-2026-25099](https://github.com/yahiahamza/CVE-2026-25099) :  ![starts](https://img.shields.io/github/stars/yahiahamza/CVE-2026-25099.svg) ![forks](https://img.shields.io/github/forks/yahiahamza/CVE-2026-25099.svg)

## CVE-2026-25075
 strongSwan versions 4.5.0 prior to 6.0.5 contain an integer underflow vulnerability in the EAP-TTLS AVP parser that allows unauthenticated remote attackers to cause a denial of service by sending crafted AVP data with invalid length fields during IKEv2 authentication. Attackers can exploit the failure to validate AVP length fields before subtraction to trigger excessive memory allocation or NULL pointer dereference, crashing the charon IKE daemon.



- [https://github.com/BishopFox/CVE-2026-25075-check](https://github.com/BishopFox/CVE-2026-25075-check) :  ![starts](https://img.shields.io/github/stars/BishopFox/CVE-2026-25075-check.svg) ![forks](https://img.shields.io/github/forks/BishopFox/CVE-2026-25075-check.svg)

## CVE-2026-25053
 n8n is an open source workflow automation platform. Prior to versions 1.123.10 and 2.5.0, vulnerabilities in the Git node allowed authenticated users with permission to create or modify workflows to execute arbitrary system commands or read arbitrary files on the n8n host. This issue has been patched in versions 1.123.10 and 2.5.0.



- [https://github.com/yadhukrishnam/CVE-2026-25053](https://github.com/yadhukrishnam/CVE-2026-25053) :  ![starts](https://img.shields.io/github/stars/yadhukrishnam/CVE-2026-25053.svg) ![forks](https://img.shields.io/github/forks/yadhukrishnam/CVE-2026-25053.svg)

## CVE-2026-25050
 Vendure is an open-source headless commerce platform. Prior to version 3.5.3, the `NativeAuthenticationStrategy.authenticate()` method is vulnerable to a timing attack that allows attackers to enumerate valid usernames (email addresses). In `packages/core/src/config/auth/native-authentication-strategy.ts`, the authenticate method returns immediately if a user is not found. The significant timing difference (~200-400ms for bcrypt vs ~1-5ms for DB miss) allows attackers to reliably distinguish between existing and non-existing accounts. Version 3.5.3 fixes the issue.



- [https://github.com/Christbowel/CVE-2026-25050](https://github.com/Christbowel/CVE-2026-25050) :  ![starts](https://img.shields.io/github/stars/Christbowel/CVE-2026-25050.svg) ![forks](https://img.shields.io/github/forks/Christbowel/CVE-2026-25050.svg)

## CVE-2026-25049
 n8n is an open source workflow automation platform. Prior to versions 1.123.17 and 2.5.2, an authenticated user with permission to create or modify workflows could abuse crafted expressions in workflow parameters to trigger unintended system command execution on the host running n8n. This issue has been patched in versions 1.123.17 and 2.5.2.



- [https://github.com/otakuliu/Expression-Sandbox-Escape-Simulation-Lab](https://github.com/otakuliu/Expression-Sandbox-Escape-Simulation-Lab) :  ![starts](https://img.shields.io/github/stars/otakuliu/Expression-Sandbox-Escape-Simulation-Lab.svg) ![forks](https://img.shields.io/github/forks/otakuliu/Expression-Sandbox-Escape-Simulation-Lab.svg)

- [https://github.com/0xBlackash/CVE-2026-25049](https://github.com/0xBlackash/CVE-2026-25049) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-25049.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-25049.svg)

## CVE-2026-25047
 deepHas provides a test for the existence of a nested object key and optionally returns that key. A prototype pollution vulnerability exists in version 1.0.7 of the deephas npm package that allows an attacker to modify global object behavior. This issue was fixed in version 1.0.8.



- [https://github.com/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-](https://github.com/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-.svg)

## CVE-2026-24858
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] vulnerability in Fortinet FortiAnalyzer 7.6.0 through 7.6.5, FortiAnalyzer 7.4.0 through 7.4.9, FortiAnalyzer 7.2.0 through 7.2.11, FortiAnalyzer 7.0.0 through 7.0.15, FortiManager 7.6.0 through 7.6.5, FortiManager 7.4.0 through 7.4.9, FortiManager 7.2.0 through 7.2.11, FortiManager 7.0.0 through 7.0.15, FortiOS 7.6.0 through 7.6.5, FortiOS 7.4.0 through 7.4.10, FortiOS 7.2.0 through 7.2.12, FortiOS 7.0.0 through 7.0.18, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4.0 through 7.4.12, FortiProxy 7.2.0 through 7.2.15, FortiProxy 7.0.0 through 7.0.22, FortiWeb 8.0.0 through 8.0.3, FortiWeb 7.6.0 through 7.6.6, FortiWeb 7.4.0 through 7.4.11 may allow an attacker with a FortiCloud account and a registered device to log into other devices registered to other accounts, if FortiCloud SSO authentication is enabled on those devices.



- [https://github.com/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass](https://github.com/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/absholi7ly/CVE-2026-24858-FortiCloud-SSO-Authentication-Bypass.svg)

- [https://github.com/gagaltotal/cve-2026-24858](https://github.com/gagaltotal/cve-2026-24858) :  ![starts](https://img.shields.io/github/stars/gagaltotal/cve-2026-24858.svg) ![forks](https://img.shields.io/github/forks/gagaltotal/cve-2026-24858.svg)

- [https://github.com/m0d0ri205/CVE-2026-24858](https://github.com/m0d0ri205/CVE-2026-24858) :  ![starts](https://img.shields.io/github/stars/m0d0ri205/CVE-2026-24858.svg) ![forks](https://img.shields.io/github/forks/m0d0ri205/CVE-2026-24858.svg)

- [https://github.com/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-](https://github.com/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-CTT-NSP-Convergent-Time-Theory---Network-Stack-Projection-CVE-2026-24858-.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity.svg)

## CVE-2026-24854
 ChurchCRM is an open-source church management system. A SQL Injection vulnerability exists in endpoint `/PaddleNumEditor.php` in ChurchCRM prior to version 6.7.2. Any authenticated user, including one with zero assigned permissions, can exploit SQL injection through the `PerID` parameter. Version 6.7.2 contains a patch for the issue.



- [https://github.com/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection](https://github.com/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-24854-ChurchCRM-6.7.2-Authenticated-Numeric-SQL-Injection.svg)

## CVE-2026-24841
 Dokploy is a free, self-hostable Platform as a Service (PaaS). In versions prior to 0.26.6, a critical command injection vulnerability exists in Dokploy's WebSocket endpoint `/docker-container-terminal`. The `containerId` and `activeWay` parameters are directly interpolated into shell commands without sanitization, allowing authenticated attackers to execute arbitrary commands on the host server. Version 0.26.6 fixes the issue.



- [https://github.com/otakuliu/CVE-2026-24841_Range](https://github.com/otakuliu/CVE-2026-24841_Range) :  ![starts](https://img.shields.io/github/stars/otakuliu/CVE-2026-24841_Range.svg) ![forks](https://img.shields.io/github/forks/otakuliu/CVE-2026-24841_Range.svg)

## CVE-2026-24688
 pypdf is a free and open-source pure-python PDF library. An attacker who uses an infinite loop vulnerability that is present in versions prior to 6.6.2 can craft a PDF which leads to an infinite loop. This requires accessing the outlines/bookmarks. This has been fixed in pypdf 6.6.2. If projects cannot upgrade yet, consider applying the changes from PR #3610 manually.



- [https://github.com/JoakimBulow/CVE-2026-24688](https://github.com/JoakimBulow/CVE-2026-24688) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-24688.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-24688.svg)

## CVE-2026-24516
 A command injection vulnerability exists in DigitalOcean Droplet Agent through 1.3.2. The troubleshooting actioner component (internal/troubleshooting/actioner/actioner.go) processes metadata from the metadata service endpoint and executes commands specified in the TroubleshootingAgent.Requesting array without adequate input validation. While the code validates that artifacts exist in the validInvestigationArtifacts map, it fails to sanitize the actual command content after the "command:" prefix. This allows an attacker who can control metadata responses to inject and execute arbitrary OS commands with root privileges. The attack is triggered by sending a TCP packet with specific sequence numbers to the SSH port, which causes the agent to fetch metadata from http://169.254.169.254/metadata/v1.json. The vulnerability affects the command execution flow in internal/troubleshooting/actioner/actioner.go (insufficient validation), internal/troubleshooting/command/exec.go (direct exec.CommandContext call), and internal/troubleshooting/command/command.go (command parsing without sanitization). This can lead to complete system compromise, data exfiltration, privilege escalation, and potential lateral movement across cloud infrastructure.



- [https://github.com/poxsky/CVE-2026-24516-DigitalOcean-RCE](https://github.com/poxsky/CVE-2026-24516-DigitalOcean-RCE) :  ![starts](https://img.shields.io/github/stars/poxsky/CVE-2026-24516-DigitalOcean-RCE.svg) ![forks](https://img.shields.io/github/forks/poxsky/CVE-2026-24516-DigitalOcean-RCE.svg)

- [https://github.com/poxsky/CVE-2026-24516-DigitalOcean-RCE.](https://github.com/poxsky/CVE-2026-24516-DigitalOcean-RCE.) :  ![starts](https://img.shields.io/github/stars/poxsky/CVE-2026-24516-DigitalOcean-RCE..svg) ![forks](https://img.shields.io/github/forks/poxsky/CVE-2026-24516-DigitalOcean-RCE..svg)

## CVE-2026-24514
 A security issue was discovered in ingress-nginx where the validating admission controller feature is subject to a denial of service condition. By sending large requests to the validating admission controller, an attacker can cause memory consumption, which may result in the ingress-nginx controller pod being killed or the node running out of memory.



- [https://github.com/mbanyamer/cve-2026-24514-Kubernetes-Dos](https://github.com/mbanyamer/cve-2026-24514-Kubernetes-Dos) :  ![starts](https://img.shields.io/github/stars/mbanyamer/cve-2026-24514-Kubernetes-Dos.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/cve-2026-24514-Kubernetes-Dos.svg)

## CVE-2026-24512
 A security issue was discovered in ingress-nginx where the `rules.http.paths.path` Ingress field can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)



- [https://github.com/mghouse17/dependency-guardian-real-advisory-demo](https://github.com/mghouse17/dependency-guardian-real-advisory-demo) :  ![starts](https://img.shields.io/github/stars/mghouse17/dependency-guardian-real-advisory-demo.svg) ![forks](https://img.shields.io/github/forks/mghouse17/dependency-guardian-real-advisory-demo.svg)

## CVE-2026-24423
 SmarterTools SmarterMail versions prior to build 9511 contain an unauthenticated remote code execution vulnerability in the ConnectToHub API method. The attacker could point the SmarterMail to the malicious HTTP server, which serves the malicious OS command. This command will be executed by the vulnerable application.



- [https://github.com/aavamin/CVE-2026-24423](https://github.com/aavamin/CVE-2026-24423) :  ![starts](https://img.shields.io/github/stars/aavamin/CVE-2026-24423.svg) ![forks](https://img.shields.io/github/forks/aavamin/CVE-2026-24423.svg)

## CVE-2026-24419
 OpenSTAManager is an open source management software for technical assistance and invoicing. OpenSTAManager v2.9.8 and earlier contain a critical Error-Based SQL Injection vulnerability in the Prima Nota (Journal Entry) module's add.php file. The application fails to validate that comma-separated values from the id_documenti GET parameter are integers before using them in SQL IN() clauses, allowing attackers to inject arbitrary SQL commands and extract sensitive data through XPATH error messages.



- [https://github.com/lukasz-rybak/CVE-2026-24419](https://github.com/lukasz-rybak/CVE-2026-24419) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-24419.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-24419.svg)

## CVE-2026-24418
 OpenSTAManager is an open source management software for technical assistance and invoicing. OpenSTAManager v2.9.8 and earlier contain a critical Error-Based SQL Injection vulnerability in the bulk operations handler for the Scadenzario (Payment Schedule) module. The application fails to validate that elements of the id_records array are integers before using them in an SQL IN() clause, allowing attackers to inject arbitrary SQL commands and extract sensitive data through XPATH error messages.



- [https://github.com/lukasz-rybak/CVE-2026-24418](https://github.com/lukasz-rybak/CVE-2026-24418) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-24418.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-24418.svg)

## CVE-2026-24417
 OpenSTAManager is an open source management software for technical assistance and invoicing. OpenSTAManager v2.9.8 and earlier contain a critical Time-Based Blind SQL Injection vulnerability in the global search functionality. The application fails to properly sanitize the term parameter before using it in SQL LIKE clauses across multiple module-specific search handlers, allowing attackers to inject arbitrary SQL commands and extract sensitive data through time-based Boolean inference.



- [https://github.com/lukasz-rybak/CVE-2026-24417](https://github.com/lukasz-rybak/CVE-2026-24417) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-24417.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-24417.svg)

## CVE-2026-24416
 OpenSTAManager is an open source management software for technical assistance and invoicing. OpenSTAManager v2.9.8 and earlier contain a critical Time-Based Blind SQL Injection vulnerability in the article pricing completion handler. The application fails to properly sanitize the idarticolo parameter before using it in SQL queries, allowing attackers to inject arbitrary SQL commands and extract sensitive data through time-based Boolean inference.



- [https://github.com/lukasz-rybak/CVE-2026-24416](https://github.com/lukasz-rybak/CVE-2026-24416) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-24416.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-24416.svg)

## CVE-2026-24415
 OpenSTAManager is an open source management software for technical assistance and invoicing. OpenSTAManager v2.9.8 and earlier contains Reflected XSS vulnerabilities in invoice/order/contract modification modals. The application fails to properly sanitize user-supplied input from the righe GET parameter before reflecting it in HTML output.The $_GET['righe'] parameter is directly echoed into the HTML value attribute without any sanitization using htmlspecialchars() or equivalent functions. This allows an attacker to break out of the attribute context and inject arbitrary HTML/JavaScript.



- [https://github.com/lukasz-rybak/CVE-2026-24415](https://github.com/lukasz-rybak/CVE-2026-24415) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-24415.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-24415.svg)

## CVE-2026-24306
 Improper access control in Azure Front Door (AFD) allows an unauthorized attacker to elevate privileges over a network.



- [https://github.com/ExploreUnknowed/CVE-2026-24306](https://github.com/ExploreUnknowed/CVE-2026-24306) :  ![starts](https://img.shields.io/github/stars/ExploreUnknowed/CVE-2026-24306.svg) ![forks](https://img.shields.io/github/forks/ExploreUnknowed/CVE-2026-24306.svg)

## CVE-2026-24294
 Improper authentication in Windows SMB Server allows an authorized attacker to elevate privileges locally.



- [https://github.com/0xNDI/CVE-2026-24294](https://github.com/0xNDI/CVE-2026-24294) :  ![starts](https://img.shields.io/github/stars/0xNDI/CVE-2026-24294.svg) ![forks](https://img.shields.io/github/forks/0xNDI/CVE-2026-24294.svg)

## CVE-2026-24291
 Incorrect permission assignment for critical resource in Windows Accessibility Infrastructure (ATBroker.exe) allows an authorized attacker to elevate privileges locally.



- [https://github.com/lennertdefauw/CVE-2026-24291](https://github.com/lennertdefauw/CVE-2026-24291) :  ![starts](https://img.shields.io/github/stars/lennertdefauw/CVE-2026-24291.svg) ![forks](https://img.shields.io/github/forks/lennertdefauw/CVE-2026-24291.svg)

- [https://github.com/n0isegat3/RegPwnBRc4BOF](https://github.com/n0isegat3/RegPwnBRc4BOF) :  ![starts](https://img.shields.io/github/stars/n0isegat3/RegPwnBRc4BOF.svg) ![forks](https://img.shields.io/github/forks/n0isegat3/RegPwnBRc4BOF.svg)

- [https://github.com/tracyliving606/RegPwn](https://github.com/tracyliving606/RegPwn) :  ![starts](https://img.shields.io/github/stars/tracyliving606/RegPwn.svg) ![forks](https://img.shields.io/github/forks/tracyliving606/RegPwn.svg)

- [https://github.com/uname1able/CVE-2026-24291](https://github.com/uname1able/CVE-2026-24291) :  ![starts](https://img.shields.io/github/stars/uname1able/CVE-2026-24291.svg) ![forks](https://img.shields.io/github/forks/uname1able/CVE-2026-24291.svg)

## CVE-2026-24135
 Gogs is an open source self-hosted Git service. In version 0.13.3 and prior, a path traversal vulnerability exists in the updateWikiPage function of Gogs. The vulnerability allows an authenticated user with write access to a repository's wiki to delete arbitrary files on the server by manipulating the old_title parameter in the wiki editing form. This issue has been patched in versions 0.13.4 and 0.14.0+dev.



- [https://github.com/reschjonas/CVE-2026-24135](https://github.com/reschjonas/CVE-2026-24135) :  ![starts](https://img.shields.io/github/stars/reschjonas/CVE-2026-24135.svg) ![forks](https://img.shields.io/github/forks/reschjonas/CVE-2026-24135.svg)

## CVE-2026-24134
 StudioCMS is a server-side-rendered, Astro native, headless content management system. Versions prior to 0.2.0 contain a Broken Object Level Authorization (BOLA) vulnerability in the Content Management feature that allows users with the "Visitor" role to access draft content created by Editor/Admin/Owner users. Version 0.2.0 patches the issue.



- [https://github.com/FilipeGaudard/CVE-2026-24134-PoC](https://github.com/FilipeGaudard/CVE-2026-24134-PoC) :  ![starts](https://img.shields.io/github/stars/FilipeGaudard/CVE-2026-24134-PoC.svg) ![forks](https://img.shields.io/github/forks/FilipeGaudard/CVE-2026-24134-PoC.svg)

## CVE-2026-24126
 Weblate is a web based localization tool. Prior to 5.16.0, the SSH management console did not validate the passed input while adding the SSH host key, which could lead to an argument injection to `ssh-add`. Version 5.16.0 fixes the issue. As a workaround, properly limit access to the management console.



- [https://github.com/alexb616/Weblate-CVE-2026-24126](https://github.com/alexb616/Weblate-CVE-2026-24126) :  ![starts](https://img.shields.io/github/stars/alexb616/Weblate-CVE-2026-24126.svg) ![forks](https://img.shields.io/github/forks/alexb616/Weblate-CVE-2026-24126.svg)

## CVE-2026-24118
 vm2 is an open source vm/sandbox for Node.js. Prior to version 3.11.0, VM2 suffers from a sandbox breakout vulnerability. This allows attackers to write code which can escape from the VM2 sandbox and execute arbitrary commands on the host system. This issue has been patched in version 3.11.0.



- [https://github.com/HORKimhab/CVE-2026-24118](https://github.com/HORKimhab/CVE-2026-24118) :  ![starts](https://img.shields.io/github/stars/HORKimhab/CVE-2026-24118.svg) ![forks](https://img.shields.io/github/forks/HORKimhab/CVE-2026-24118.svg)

## CVE-2026-24072
 An escalation of privilege bug in various modules in Apache HTTP 2.4.66 and earlier allows local .htaccess authors to read files with the privileges of the httpd user.

Users are recommended to upgrade to version 2.4.67, which fixes this issue.



- [https://github.com/EricRHancock-coder/CVE-2026-24072-Analysis](https://github.com/EricRHancock-coder/CVE-2026-24072-Analysis) :  ![starts](https://img.shields.io/github/stars/EricRHancock-coder/CVE-2026-24072-Analysis.svg) ![forks](https://img.shields.io/github/forks/EricRHancock-coder/CVE-2026-24072-Analysis.svg)

## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.



- [https://github.com/SafeBreach-Labs/CVE-2026-24061](https://github.com/SafeBreach-Labs/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/SafeBreach-Labs/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/SafeBreach-Labs/CVE-2026-24061.svg)

- [https://github.com/JayGLXR/CVE-2026-24061-POC](https://github.com/JayGLXR/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/JayGLXR/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/JayGLXR/CVE-2026-24061-POC.svg)

- [https://github.com/parameciumzhang/Tell-Me-Root](https://github.com/parameciumzhang/Tell-Me-Root) :  ![starts](https://img.shields.io/github/stars/parameciumzhang/Tell-Me-Root.svg) ![forks](https://img.shields.io/github/forks/parameciumzhang/Tell-Me-Root.svg)

- [https://github.com/Lingzesec/CVE-2026-24061-GUI](https://github.com/Lingzesec/CVE-2026-24061-GUI) :  ![starts](https://img.shields.io/github/stars/Lingzesec/CVE-2026-24061-GUI.svg) ![forks](https://img.shields.io/github/forks/Lingzesec/CVE-2026-24061-GUI.svg)

- [https://github.com/Chocapikk/CVE-2026-24061](https://github.com/Chocapikk/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2026-24061.svg)

- [https://github.com/ilostmypassword/Melissae-Honeypot-Framework](https://github.com/ilostmypassword/Melissae-Honeypot-Framework) :  ![starts](https://img.shields.io/github/stars/ilostmypassword/Melissae-Honeypot-Framework.svg) ![forks](https://img.shields.io/github/forks/ilostmypassword/Melissae-Honeypot-Framework.svg)

- [https://github.com/leonjza/inetutils-telnetd-auth-bypass](https://github.com/leonjza/inetutils-telnetd-auth-bypass) :  ![starts](https://img.shields.io/github/stars/leonjza/inetutils-telnetd-auth-bypass.svg) ![forks](https://img.shields.io/github/forks/leonjza/inetutils-telnetd-auth-bypass.svg)

- [https://github.com/TryA9ain/CVE-2026-24061](https://github.com/TryA9ain/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/TryA9ain/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/TryA9ain/CVE-2026-24061.svg)

- [https://github.com/h3athen/CVE-2026-24061](https://github.com/h3athen/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/h3athen/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/h3athen/CVE-2026-24061.svg)

- [https://github.com/0p5cur/CVE-2026-24061-POC](https://github.com/0p5cur/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/0p5cur/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/0p5cur/CVE-2026-24061-POC.svg)

- [https://github.com/ekomsSavior/telnet_scan](https://github.com/ekomsSavior/telnet_scan) :  ![starts](https://img.shields.io/github/stars/ekomsSavior/telnet_scan.svg) ![forks](https://img.shields.io/github/forks/ekomsSavior/telnet_scan.svg)

- [https://github.com/SystemVll/CVE-2026-24061](https://github.com/SystemVll/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2026-24061.svg)

- [https://github.com/ibrahmsql/CVE-2026-24061-PoC](https://github.com/ibrahmsql/CVE-2026-24061-PoC) :  ![starts](https://img.shields.io/github/stars/ibrahmsql/CVE-2026-24061-PoC.svg) ![forks](https://img.shields.io/github/forks/ibrahmsql/CVE-2026-24061-PoC.svg)

- [https://github.com/shivam-bathla/CVE-2026-24061-setup](https://github.com/shivam-bathla/CVE-2026-24061-setup) :  ![starts](https://img.shields.io/github/stars/shivam-bathla/CVE-2026-24061-setup.svg) ![forks](https://img.shields.io/github/forks/shivam-bathla/CVE-2026-24061-setup.svg)

- [https://github.com/xuemian168/CVE-2026-24061](https://github.com/xuemian168/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/xuemian168/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/xuemian168/CVE-2026-24061.svg)

- [https://github.com/franckferman/CVE_2026_24061](https://github.com/franckferman/CVE_2026_24061) :  ![starts](https://img.shields.io/github/stars/franckferman/CVE_2026_24061.svg) ![forks](https://img.shields.io/github/forks/franckferman/CVE_2026_24061.svg)

- [https://github.com/madfxr/Twenty-Three-Scanner](https://github.com/madfxr/Twenty-Three-Scanner) :  ![starts](https://img.shields.io/github/stars/madfxr/Twenty-Three-Scanner.svg) ![forks](https://img.shields.io/github/forks/madfxr/Twenty-Three-Scanner.svg)

- [https://github.com/balgan/CVE-2026-24061](https://github.com/balgan/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/balgan/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/balgan/CVE-2026-24061.svg)

- [https://github.com/duy-31/CVE-2026-24061---telnetd](https://github.com/duy-31/CVE-2026-24061---telnetd) :  ![starts](https://img.shields.io/github/stars/duy-31/CVE-2026-24061---telnetd.svg) ![forks](https://img.shields.io/github/forks/duy-31/CVE-2026-24061---telnetd.svg)

- [https://github.com/RStephanH/vuln-deb](https://github.com/RStephanH/vuln-deb) :  ![starts](https://img.shields.io/github/stars/RStephanH/vuln-deb.svg) ![forks](https://img.shields.io/github/forks/RStephanH/vuln-deb.svg)

- [https://github.com/hackingyseguridad/root](https://github.com/hackingyseguridad/root) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/root.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/root.svg)

- [https://github.com/0xBlackash/CVE-2026-24061](https://github.com/0xBlackash/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-24061.svg)

- [https://github.com/infat0x/CVE-2026-24061](https://github.com/infat0x/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/infat0x/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/infat0x/CVE-2026-24061.svg)

- [https://github.com/dotelpenguin/telnetd_CVE-2026-24061_tester](https://github.com/dotelpenguin/telnetd_CVE-2026-24061_tester) :  ![starts](https://img.shields.io/github/stars/dotelpenguin/telnetd_CVE-2026-24061_tester.svg) ![forks](https://img.shields.io/github/forks/dotelpenguin/telnetd_CVE-2026-24061_tester.svg)

- [https://github.com/X-croot/CVE-2026-24061_POC](https://github.com/X-croot/CVE-2026-24061_POC) :  ![starts](https://img.shields.io/github/stars/X-croot/CVE-2026-24061_POC.svg) ![forks](https://img.shields.io/github/forks/X-croot/CVE-2026-24061_POC.svg)

- [https://github.com/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-](https://github.com/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-) :  ![starts](https://img.shields.io/github/stars/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-.svg) ![forks](https://img.shields.io/github/forks/MY0723/GNU-Inetutils-telnet-CVE-2026-24061-.svg)

- [https://github.com/FurkanKAYAPINAR/CVE-2026-24061-telnet2root](https://github.com/FurkanKAYAPINAR/CVE-2026-24061-telnet2root) :  ![starts](https://img.shields.io/github/stars/FurkanKAYAPINAR/CVE-2026-24061-telnet2root.svg) ![forks](https://img.shields.io/github/forks/FurkanKAYAPINAR/CVE-2026-24061-telnet2root.svg)

- [https://github.com/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061](https://github.com/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061.svg)

- [https://github.com/ridpath/Terrminus-CVE-2026-2406](https://github.com/ridpath/Terrminus-CVE-2026-2406) :  ![starts](https://img.shields.io/github/stars/ridpath/Terrminus-CVE-2026-2406.svg) ![forks](https://img.shields.io/github/forks/ridpath/Terrminus-CVE-2026-2406.svg)

- [https://github.com/Ali-brarou/telnest](https://github.com/Ali-brarou/telnest) :  ![starts](https://img.shields.io/github/stars/Ali-brarou/telnest.svg) ![forks](https://img.shields.io/github/forks/Ali-brarou/telnest.svg)

- [https://github.com/Mefhika120/Ashwesker-CVE-2026-24061](https://github.com/Mefhika120/Ashwesker-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Mefhika120/Ashwesker-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Mefhika120/Ashwesker-CVE-2026-24061.svg)

- [https://github.com/novitahk/Exploit-CVE-2026-24061](https://github.com/novitahk/Exploit-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/novitahk/Exploit-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/novitahk/Exploit-CVE-2026-24061.svg)

- [https://github.com/r00tuser111/CVE-2026-24061](https://github.com/r00tuser111/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/r00tuser111/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/r00tuser111/CVE-2026-24061.svg)

- [https://github.com/Remnant-DB/CVE-2026-24061](https://github.com/Remnant-DB/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Remnant-DB/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Remnant-DB/CVE-2026-24061.svg)

- [https://github.com/scumfrog/cve-2026-24061](https://github.com/scumfrog/cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/scumfrog/cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/scumfrog/cve-2026-24061.svg)

- [https://github.com/buzz075/CVE-2026-24061](https://github.com/buzz075/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/buzz075/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/buzz075/CVE-2026-24061.svg)

- [https://github.com/Mr-Zapi/CVE-2026-24061](https://github.com/Mr-Zapi/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Mr-Zapi/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Mr-Zapi/CVE-2026-24061.svg)

- [https://github.com/XsanFlip/CVE-2026-24061-Scanner](https://github.com/XsanFlip/CVE-2026-24061-Scanner) :  ![starts](https://img.shields.io/github/stars/XsanFlip/CVE-2026-24061-Scanner.svg) ![forks](https://img.shields.io/github/forks/XsanFlip/CVE-2026-24061-Scanner.svg)

- [https://github.com/przemytn/CVE-2026-24061](https://github.com/przemytn/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/przemytn/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/przemytn/CVE-2026-24061.svg)

- [https://github.com/LucasPDiniz/CVE-2026-24061](https://github.com/LucasPDiniz/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/LucasPDiniz/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/LucasPDiniz/CVE-2026-24061.svg)

- [https://github.com/z3n70/CVE-2026-24061](https://github.com/z3n70/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/z3n70/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/z3n70/CVE-2026-24061.svg)

- [https://github.com/Parad0x7e/CVE-2026-24061](https://github.com/Parad0x7e/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/Parad0x7e/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/Parad0x7e/CVE-2026-24061.svg)

- [https://github.com/BrainBob/CVE-2026-24061](https://github.com/BrainBob/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/BrainBob/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/BrainBob/CVE-2026-24061.svg)

- [https://github.com/SeptembersEND/CVE--2026-24061](https://github.com/SeptembersEND/CVE--2026-24061) :  ![starts](https://img.shields.io/github/stars/SeptembersEND/CVE--2026-24061.svg) ![forks](https://img.shields.io/github/forks/SeptembersEND/CVE--2026-24061.svg)

- [https://github.com/typeconfused/CVE-2026-24061](https://github.com/typeconfused/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/typeconfused/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/typeconfused/CVE-2026-24061.svg)

- [https://github.com/tiborscholtz/CVE-2026-24061](https://github.com/tiborscholtz/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/tiborscholtz/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/tiborscholtz/CVE-2026-24061.svg)

- [https://github.com/monstertsl/CVE-2026-24061](https://github.com/monstertsl/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/monstertsl/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/monstertsl/CVE-2026-24061.svg)

- [https://github.com/0x7556/CVE-2026-24061](https://github.com/0x7556/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0x7556/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0x7556/CVE-2026-24061.svg)

- [https://github.com/Gabs-hub/CVE-2026-24061_Lab](https://github.com/Gabs-hub/CVE-2026-24061_Lab) :  ![starts](https://img.shields.io/github/stars/Gabs-hub/CVE-2026-24061_Lab.svg) ![forks](https://img.shields.io/github/forks/Gabs-hub/CVE-2026-24061_Lab.svg)

- [https://github.com/obrunolima1910/CVE-2026-24061](https://github.com/obrunolima1910/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/obrunolima1910/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/obrunolima1910/CVE-2026-24061.svg)

- [https://github.com/midox008/CVE-2026-24061](https://github.com/midox008/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/midox008/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/midox008/CVE-2026-24061.svg)

- [https://github.com/HD0x01/CVE-2026-24061-NSE](https://github.com/HD0x01/CVE-2026-24061-NSE) :  ![starts](https://img.shields.io/github/stars/HD0x01/CVE-2026-24061-NSE.svg) ![forks](https://img.shields.io/github/forks/HD0x01/CVE-2026-24061-NSE.svg)

- [https://github.com/killsystema/scan-cve-2026-24061](https://github.com/killsystema/scan-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/killsystema/scan-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/killsystema/scan-cve-2026-24061.svg)

- [https://github.com/ms0x08-dev/CVE-2026-24061-POC](https://github.com/ms0x08-dev/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/ms0x08-dev/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/ms0x08-dev/CVE-2026-24061-POC.svg)

- [https://github.com/m3ngx1ng/cve_2026_24061_cli](https://github.com/m3ngx1ng/cve_2026_24061_cli) :  ![starts](https://img.shields.io/github/stars/m3ngx1ng/cve_2026_24061_cli.svg) ![forks](https://img.shields.io/github/forks/m3ngx1ng/cve_2026_24061_cli.svg)

- [https://github.com/Alter-N0X/CVE-2026-24061-POC](https://github.com/Alter-N0X/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/Alter-N0X/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/Alter-N0X/CVE-2026-24061-POC.svg)

- [https://github.com/lavabyte/telnet-CVE-2026-24061](https://github.com/lavabyte/telnet-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/lavabyte/telnet-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/lavabyte/telnet-CVE-2026-24061.svg)

- [https://github.com/punitdarji/telnetd-cve-2026-24061](https://github.com/punitdarji/telnetd-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/punitdarji/telnetd-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/punitdarji/telnetd-cve-2026-24061.svg)

- [https://github.com/canpilayda/inetutils-telnetd-cve-2026-24061](https://github.com/canpilayda/inetutils-telnetd-cve-2026-24061) :  ![starts](https://img.shields.io/github/stars/canpilayda/inetutils-telnetd-cve-2026-24061.svg) ![forks](https://img.shields.io/github/forks/canpilayda/inetutils-telnetd-cve-2026-24061.svg)

- [https://github.com/BrainBob/Telnet-TestVuln-CVE-2026-24061](https://github.com/BrainBob/Telnet-TestVuln-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/BrainBob/Telnet-TestVuln-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/BrainBob/Telnet-TestVuln-CVE-2026-24061.svg)

- [https://github.com/androidteacher/CVE-2026-24061-PoC-Telnetd](https://github.com/androidteacher/CVE-2026-24061-PoC-Telnetd) :  ![starts](https://img.shields.io/github/stars/androidteacher/CVE-2026-24061-PoC-Telnetd.svg) ![forks](https://img.shields.io/github/forks/androidteacher/CVE-2026-24061-PoC-Telnetd.svg)

- [https://github.com/athack-ctf/chall2026-telneted](https://github.com/athack-ctf/chall2026-telneted) :  ![starts](https://img.shields.io/github/stars/athack-ctf/chall2026-telneted.svg) ![forks](https://img.shields.io/github/forks/athack-ctf/chall2026-telneted.svg)

- [https://github.com/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector](https://github.com/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector) :  ![starts](https://img.shields.io/github/stars/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector.svg) ![forks](https://img.shields.io/github/forks/nrnw/CVE-2026-24061-GNU-inetutils-Telnet-Detector.svg)

- [https://github.com/Risma2025/CVE-2026-24061-GNU-InetUtils-telnetd-Authentication-Bypass-Vulnerability](https://github.com/Risma2025/CVE-2026-24061-GNU-InetUtils-telnetd-Authentication-Bypass-Vulnerability) :  ![starts](https://img.shields.io/github/stars/Risma2025/CVE-2026-24061-GNU-InetUtils-telnetd-Authentication-Bypass-Vulnerability.svg) ![forks](https://img.shields.io/github/forks/Risma2025/CVE-2026-24061-GNU-InetUtils-telnetd-Authentication-Bypass-Vulnerability.svg)

- [https://github.com/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-](https://github.com/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-24061-GNU-Inetutils-telnetd-Remote-Authentication-Bypass-Root-Shell-.svg)

- [https://github.com/setuju/telnetd](https://github.com/setuju/telnetd) :  ![starts](https://img.shields.io/github/stars/setuju/telnetd.svg) ![forks](https://img.shields.io/github/forks/setuju/telnetd.svg)

- [https://github.com/cumakurt/tscan](https://github.com/cumakurt/tscan) :  ![starts](https://img.shields.io/github/stars/cumakurt/tscan.svg) ![forks](https://img.shields.io/github/forks/cumakurt/tscan.svg)

- [https://github.com/hyu164/Terrminus-CVE-2026-2406](https://github.com/hyu164/Terrminus-CVE-2026-2406) :  ![starts](https://img.shields.io/github/stars/hyu164/Terrminus-CVE-2026-2406.svg) ![forks](https://img.shields.io/github/forks/hyu164/Terrminus-CVE-2026-2406.svg)

## CVE-2026-24049
 wheel is a command line tool for manipulating Python wheel files, as defined in PEP 427. In versions 0.40.0 through 0.46.1, the unpack function is vulnerable to file permission modification through mishandling of file permissions after extraction. The logic blindly trusts the filename from the archive header for the chmod operation, even though the extraction process itself might have sanitized the path. Attackers can craft a malicious wheel file that, when unpacked, changes the permissions of critical system files (e.g., /etc/passwd, SSH keys, config files), allowing for Privilege Escalation or arbitrary code execution by modifying now-writable scripts. This issue has been fixed in version 0.46.2.



- [https://github.com/kriskimmerle/wheelaudit](https://github.com/kriskimmerle/wheelaudit) :  ![starts](https://img.shields.io/github/stars/kriskimmerle/wheelaudit.svg) ![forks](https://img.shields.io/github/forks/kriskimmerle/wheelaudit.svg)

## CVE-2026-24018
 A UNIX symbolic link (Symlink) following vulnerability in Fortinet FortiClientLinux 7.4.0 through 7.4.4, FortiClientLinux 7.2.2 through 7.2.12 may allow a local and unprivileged user to escalate their privileges to root.



- [https://github.com/febin0x10/Fortinet_FortiClient_Exploit_CVE-2026-24018](https://github.com/febin0x10/Fortinet_FortiClient_Exploit_CVE-2026-24018) :  ![starts](https://img.shields.io/github/stars/febin0x10/Fortinet_FortiClient_Exploit_CVE-2026-24018.svg) ![forks](https://img.shields.io/github/forks/febin0x10/Fortinet_FortiClient_Exploit_CVE-2026-24018.svg)

## CVE-2026-24009
 Docling Core (or docling-core) is a library that defines core data types and transformations in the document processing application Docling. A PyYAML-related Remote Code Execution (RCE) vulnerability, namely CVE-2020-14343, is exposed in docling-core starting in version 2.21.0 and prior to version 2.48.4, specifically only if the application uses pyyaml prior to version 5.4 and invokes `docling_core.types.doc.DoclingDocument.load_from_yaml()` passing it untrusted YAML data. The vulnerability has been patched in docling-core version 2.48.4. The fix mitigates the issue by switching `PyYAML` deserialization from `yaml.FullLoader` to `yaml.SafeLoader`, ensuring that untrusted data cannot trigger code execution. Users who cannot immediately upgrade docling-core can alternatively ensure that the installed version of PyYAML is 5.4 or greater.



- [https://github.com/BiranPeretz/docling-core-CVE-2026-24009](https://github.com/BiranPeretz/docling-core-CVE-2026-24009) :  ![starts](https://img.shields.io/github/stars/BiranPeretz/docling-core-CVE-2026-24009.svg) ![forks](https://img.shields.io/github/forks/BiranPeretz/docling-core-CVE-2026-24009.svg)

## CVE-2026-23980
 Improper Neutralization of Special Elements used in a SQL Command ('SQL Injection') vulnerability in Apache Superset allows an authenticated user with read access to conduct error-based SQL injection via the sqlExpression or where parameters.

This issue affects Apache Superset: before 6.0.0.

Users are recommended to upgrade to version 6.0.0, which fixes the issue.



- [https://github.com/oscar-mine/CVE-2026-23980-Exploit](https://github.com/oscar-mine/CVE-2026-23980-Exploit) :  ![starts](https://img.shields.io/github/stars/oscar-mine/CVE-2026-23980-Exploit.svg) ![forks](https://img.shields.io/github/forks/oscar-mine/CVE-2026-23980-Exploit.svg)

## CVE-2026-23947
 Orval generates type-safe JS clients (TypeScript) from any valid OpenAPI v3 or Swagger v2 specification. Versions prior to 7.19.0 until 8.0.2 are vulnerable to arbitrary code execution in environments consuming generated clients. This issue is similar in nature to CVE-2026-22785, but affects a different code path in @orval/core that was not addressed by CVE-2026-22785's fix. The vulnerability allows untrusted OpenAPI specifications to inject arbitrary TypeScript/JavaScript code into generated clients via the x-enumDescriptions field, which is embedded without proper escaping in getEnumImplementation(). I have confirmed that the injection occurs during const enum generation and results in executable code within the generated schema files. Orval 7.19.0 and 8.0.2 contain a fix for the issue.



- [https://github.com/boroeurnprach/CVE-2026-23947-PoC](https://github.com/boroeurnprach/CVE-2026-23947-PoC) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/CVE-2026-23947-PoC.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/CVE-2026-23947-PoC.svg)

## CVE-2026-23918
 Double Free and possible RCE vulnerability in Apache HTTP Server with the HTTP/2 protocol.

This issue affects Apache HTTP Server: 2.4.66.

Users are recommended to upgrade to version 2.4.67, which fixes the issue.



- [https://github.com/xeloxa/CVE-2026-23918-Apache-H2-PoC](https://github.com/xeloxa/CVE-2026-23918-Apache-H2-PoC) :  ![starts](https://img.shields.io/github/stars/xeloxa/CVE-2026-23918-Apache-H2-PoC.svg) ![forks](https://img.shields.io/github/forks/xeloxa/CVE-2026-23918-Apache-H2-PoC.svg)

- [https://github.com/rhasan-com/CVE-2026-23918](https://github.com/rhasan-com/CVE-2026-23918) :  ![starts](https://img.shields.io/github/stars/rhasan-com/CVE-2026-23918.svg) ![forks](https://img.shields.io/github/forks/rhasan-com/CVE-2026-23918.svg)

- [https://github.com/qassam-315/CVE-2026-23918-Elite-Auditor](https://github.com/qassam-315/CVE-2026-23918-Elite-Auditor) :  ![starts](https://img.shields.io/github/stars/qassam-315/CVE-2026-23918-Elite-Auditor.svg) ![forks](https://img.shields.io/github/forks/qassam-315/CVE-2026-23918-Elite-Auditor.svg)

- [https://github.com/12lie20/CVE-2026-23918-test](https://github.com/12lie20/CVE-2026-23918-test) :  ![starts](https://img.shields.io/github/stars/12lie20/CVE-2026-23918-test.svg) ![forks](https://img.shields.io/github/forks/12lie20/CVE-2026-23918-test.svg)

- [https://github.com/seguridadentrerios/CVE-2026-23918](https://github.com/seguridadentrerios/CVE-2026-23918) :  ![starts](https://img.shields.io/github/stars/seguridadentrerios/CVE-2026-23918.svg) ![forks](https://img.shields.io/github/forks/seguridadentrerios/CVE-2026-23918.svg)

- [https://github.com/alt3kx/CVE-2026-23918](https://github.com/alt3kx/CVE-2026-23918) :  ![starts](https://img.shields.io/github/stars/alt3kx/CVE-2026-23918.svg) ![forks](https://img.shields.io/github/forks/alt3kx/CVE-2026-23918.svg)

- [https://github.com/hackervlogofficial/CVE-2026-23918](https://github.com/hackervlogofficial/CVE-2026-23918) :  ![starts](https://img.shields.io/github/stars/hackervlogofficial/CVE-2026-23918.svg) ![forks](https://img.shields.io/github/forks/hackervlogofficial/CVE-2026-23918.svg)

- [https://github.com/insomnisec/Detections-CVE-2026-23918](https://github.com/insomnisec/Detections-CVE-2026-23918) :  ![starts](https://img.shields.io/github/stars/insomnisec/Detections-CVE-2026-23918.svg) ![forks](https://img.shields.io/github/forks/insomnisec/Detections-CVE-2026-23918.svg)

- [https://github.com/aa022/CVE-2026-23918-Passive-Audit](https://github.com/aa022/CVE-2026-23918-Passive-Audit) :  ![starts](https://img.shields.io/github/stars/aa022/CVE-2026-23918-Passive-Audit.svg) ![forks](https://img.shields.io/github/forks/aa022/CVE-2026-23918-Passive-Audit.svg)

- [https://github.com/CYFARE/CVE-2026-23918-Apache-HTTP-Server-DoubleFree-PoC](https://github.com/CYFARE/CVE-2026-23918-Apache-HTTP-Server-DoubleFree-PoC) :  ![starts](https://img.shields.io/github/stars/CYFARE/CVE-2026-23918-Apache-HTTP-Server-DoubleFree-PoC.svg) ![forks](https://img.shields.io/github/forks/CYFARE/CVE-2026-23918-Apache-HTTP-Server-DoubleFree-PoC.svg)

- [https://github.com/rshosting/Apache-CVE-2026-23918-fix](https://github.com/rshosting/Apache-CVE-2026-23918-fix) :  ![starts](https://img.shields.io/github/stars/rshosting/Apache-CVE-2026-23918-fix.svg) ![forks](https://img.shields.io/github/forks/rshosting/Apache-CVE-2026-23918-fix.svg)

## CVE-2026-23907
 This issue affects the 
ExtractEmbeddedFiles example in Apache PDFBox: from 2.0.24 through 2.0.35, from 3.0.0 through 3.0.6.


The ExtractEmbeddedFiles example contains a path traversal vulnerability (CWE-22) because 
the filename that is obtained from 
PDComplexFileSpecification.getFilename() is appended to the extraction path.

Users who have copied this example into their production code should 
review it to ensure that the extraction path is acceptable. The example 
has been changed accordingly, now the initial path and the extraction 
paths are converted into canonical paths and it is verified that 
extraction path contains the initial path. The documentation has also 
been adjusted.



- [https://github.com/JoakimBulow/CVE-2026-23907](https://github.com/JoakimBulow/CVE-2026-23907) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-23907.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-23907.svg)

## CVE-2026-23885
 Alchemy is an open source content management system engine written in Ruby on Rails. Prior to versions 7.4.12 and 8.0.3, the application uses the Ruby `eval()` function to dynamically execute a string provided by the `resource_handler.engine_name` attribute in `Alchemy::ResourcesHelper#resource_url_proxy`. The vulnerability exists in `app/helpers/alchemy/resources_helper.rb` at line 28. The code explicitly bypasses security linting with `# rubocop:disable Security/Eval`, indicating that the use of a dangerous function was known but not properly mitigated. Since `engine_name` is sourced from module definitions that can be influenced by administrative configurations, it allows an authenticated attacker to escape the Ruby sandbox and execute arbitrary system commands on the host OS. Versions 7.4.12 and 8.0.3 fix the issue by replacing `eval()` with `send()`.



- [https://github.com/TheDeepOpc/CVE-2026-23885](https://github.com/TheDeepOpc/CVE-2026-23885) :  ![starts](https://img.shields.io/github/stars/TheDeepOpc/CVE-2026-23885.svg) ![forks](https://img.shields.io/github/forks/TheDeepOpc/CVE-2026-23885.svg)

## CVE-2026-23870
 A denial of service vulnerability could be triggered by sending specially crafted HTTP requests to server function endpoints, this could lead to server crashes, out-of-memory exceptions or excessive CPU usage; affecting the following packages: react-server-dom-webpack, react-server-dom-parcel, react-server-dom-turbopack (versions 19.0.0 through 19.0.5, 19.1.0 through 19.1.6, and 19.2.0 through 19.2.5).



- [https://github.com/dwisiswant0/next-16.2.4-pocs](https://github.com/dwisiswant0/next-16.2.4-pocs) :  ![starts](https://img.shields.io/github/stars/dwisiswant0/next-16.2.4-pocs.svg) ![forks](https://img.shields.io/github/forks/dwisiswant0/next-16.2.4-pocs.svg)

## CVE-2026-23869
 A denial of service vulnerability exists in React Server Components, affecting the following packages: react-server-dom-parcel, react-server-dom-turbopack and react-server-dom-webpack (versions 19.0.0 through 19.0.4, 19.1.0 through 19.1.5, and 19.2.0 through 19.2.4). The vulnerability is triggered by sending specially crafted HTTP requests to Server Function endpoints.The payload of the HTTP request causes excessive CPU usage for up to a minute ending in a thrown error that is catchable.



- [https://github.com/cybertechajju/CVE-2026-23869-Exploit](https://github.com/cybertechajju/CVE-2026-23869-Exploit) :  ![starts](https://img.shields.io/github/stars/cybertechajju/CVE-2026-23869-Exploit.svg) ![forks](https://img.shields.io/github/forks/cybertechajju/CVE-2026-23869-Exploit.svg)

- [https://github.com/yohannslm/CVE-2026-23869](https://github.com/yohannslm/CVE-2026-23869) :  ![starts](https://img.shields.io/github/stars/yohannslm/CVE-2026-23869.svg) ![forks](https://img.shields.io/github/forks/yohannslm/CVE-2026-23869.svg)

## CVE-2026-23842
 ChatterBot is a machine learning, conversational dialog engine for creating chat bots. ChatterBot versions up to 1.2.10 are vulnerable to a denial-of-service condition caused by improper database session and connection pool management. Concurrent invocations of the get_response() method can exhaust the underlying SQLAlchemy connection pool, resulting in persistent service unavailability and requiring a manual restart to recover. Version 1.2.11 fixes the issue.



- [https://github.com/AdityaBhatt3010/CVE-2026-23842-Denial-of-Service-via-Database-Connection-Pool-Exhaustion-version-1.2.10](https://github.com/AdityaBhatt3010/CVE-2026-23842-Denial-of-Service-via-Database-Connection-Pool-Exhaustion-version-1.2.10) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/CVE-2026-23842-Denial-of-Service-via-Database-Connection-Pool-Exhaustion-version-1.2.10.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/CVE-2026-23842-Denial-of-Service-via-Database-Connection-Pool-Exhaustion-version-1.2.10.svg)

## CVE-2026-23830
 SandboxJS is a JavaScript sandboxing library. Versions prior to 0.8.26 have a sandbox escape vulnerability due to `AsyncFunction` not being isolated in `SandboxFunction`. The library attempts to sandbox code execution by replacing the global `Function` constructor with a safe, sandboxed version (`SandboxFunction`). This is handled in `utils.ts` by mapping `Function` to `sandboxFunction` within a map used for lookups. However, before version 0.8.26, the library did not include mappings for `AsyncFunction`, `GeneratorFunction`, and `AsyncGeneratorFunction`. These constructors are not global properties but can be accessed via the `.constructor` property of an instance (e.g., `(async () = {}).constructor`). In `executor.ts`, property access is handled. When code running inside the sandbox accesses `.constructor` on an async function (which the sandbox allows creating), the `executor` retrieves the property value. Since `AsyncFunction` was not in the safe-replacement map, the `executor` returns the actual native host `AsyncFunction` constructor. Constructors for functions in JavaScript (like `Function`, `AsyncFunction`) create functions that execute in the global scope. By obtaining the host `AsyncFunction` constructor, an attacker can create a new async function that executes entirely outside the sandbox context, bypassing all restrictions and gaining full access to the host environment (Remote Code Execution). Version 0.8.26 patches this vulnerability.



- [https://github.com/Galaxy-sc/CVE-2026-23830-SandBreak](https://github.com/Galaxy-sc/CVE-2026-23830-SandBreak) :  ![starts](https://img.shields.io/github/stars/Galaxy-sc/CVE-2026-23830-SandBreak.svg) ![forks](https://img.shields.io/github/forks/Galaxy-sc/CVE-2026-23830-SandBreak.svg)

## CVE-2026-23829
 Mailpit is an email testing tool and API for developers. Prior to version 1.28.3, Mailpit's SMTP server is vulnerable to Header Injection due to an insufficient Regular Expression used to validate `RCPT TO` and `MAIL FROM` addresses. An attacker can inject arbitrary SMTP headers (or corrupt existing ones) by including carriage return characters (`\r`) in the email address. This header injection occurs because the regex intended to filter control characters fails to exclude `\r` and `\n` when used inside a character class. Version 1.28.3 fixes this issue.



- [https://github.com/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-](https://github.com/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-CVE-2026-23829-CTT-Mailpit-phase-reconstruction-.svg)

- [https://github.com/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover](https://github.com/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Mailpit-RCE-v1.0---Temporal-Resonance-Mail-Server-Takeover.svg)

## CVE-2026-23760
 SmarterTools SmarterMail versions prior to build 9511 contain an authentication bypass vulnerability in the password reset API. The force-reset-password endpoint permits anonymous requests and fails to verify the existing password or a reset token when resetting system administrator accounts. An unauthenticated attacker can supply a target administrator username and a new password to reset the account, resulting in full administrative compromise of the SmarterMail instance. NOTE: SmarterMail system administrator privileges grant the ability to execute operating system commands via built-in management functionality, effectively providing administrative (SYSTEM or root) access on the underlying host.



- [https://github.com/MaxMnMl/smartermail-CVE-2026-23760-poc](https://github.com/MaxMnMl/smartermail-CVE-2026-23760-poc) :  ![starts](https://img.shields.io/github/stars/MaxMnMl/smartermail-CVE-2026-23760-poc.svg) ![forks](https://img.shields.io/github/forks/MaxMnMl/smartermail-CVE-2026-23760-poc.svg)

## CVE-2026-23745
 node-tar is a Tar for Node.js. The node-tar library (= 7.5.2) fails to sanitize the linkpath of Link (hardlink) and SymbolicLink entries when preservePaths is false (the default secure behavior). This allows malicious archives to bypass the extraction root restriction, leading to Arbitrary File Overwrite via hardlinks and Symlink Poisoning via absolute symlink targets. This vulnerability is fixed in 7.5.3.



- [https://github.com/Jvr2022/CVE-2026-23745](https://github.com/Jvr2022/CVE-2026-23745) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-23745.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-23745.svg)

- [https://github.com/Novem13th/CVE-2026-23745-via-graphql-DEMO](https://github.com/Novem13th/CVE-2026-23745-via-graphql-DEMO) :  ![starts](https://img.shields.io/github/stars/Novem13th/CVE-2026-23745-via-graphql-DEMO.svg) ![forks](https://img.shields.io/github/forks/Novem13th/CVE-2026-23745-via-graphql-DEMO.svg)

## CVE-2026-23744
 MCPJam inspector is the local-first development platform for MCP servers. Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. Version 1.4.3 contains a patch.



- [https://github.com/boroeurnprach/CVE-2026-23744-PoC](https://github.com/boroeurnprach/CVE-2026-23744-PoC) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/CVE-2026-23744-PoC.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/CVE-2026-23744-PoC.svg)

- [https://github.com/FrenzisRed/CVE-2026-23744](https://github.com/FrenzisRed/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/FrenzisRed/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/FrenzisRed/CVE-2026-23744.svg)

- [https://github.com/0xg00se/CVE-2026-23744-script](https://github.com/0xg00se/CVE-2026-23744-script) :  ![starts](https://img.shields.io/github/stars/0xg00se/CVE-2026-23744-script.svg) ![forks](https://img.shields.io/github/forks/0xg00se/CVE-2026-23744-script.svg)

- [https://github.com/ctzisme/CVE-2026-23744](https://github.com/ctzisme/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/ctzisme/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/ctzisme/CVE-2026-23744.svg)

- [https://github.com/AhmadF77/CVE-2026-23744](https://github.com/AhmadF77/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/AhmadF77/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/AhmadF77/CVE-2026-23744.svg)

- [https://github.com/InzegoSec/CVE-2026-23744](https://github.com/InzegoSec/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/InzegoSec/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/InzegoSec/CVE-2026-23744.svg)

- [https://github.com/d3vn0mi/CVE-2026-23744-POC](https://github.com/d3vn0mi/CVE-2026-23744-POC) :  ![starts](https://img.shields.io/github/stars/d3vn0mi/CVE-2026-23744-POC.svg) ![forks](https://img.shields.io/github/forks/d3vn0mi/CVE-2026-23744-POC.svg)

- [https://github.com/fcjaviergarcia/CVE-2026-23744-POC](https://github.com/fcjaviergarcia/CVE-2026-23744-POC) :  ![starts](https://img.shields.io/github/stars/fcjaviergarcia/CVE-2026-23744-POC.svg) ![forks](https://img.shields.io/github/forks/fcjaviergarcia/CVE-2026-23744-POC.svg)

- [https://github.com/CyLock11/CVE-2026-23744](https://github.com/CyLock11/CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/CyLock11/CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/CyLock11/CVE-2026-23744.svg)

- [https://github.com/rootdirective-sec/CVE-2026-23744-Lab](https://github.com/rootdirective-sec/CVE-2026-23744-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-23744-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-23744-Lab.svg)

- [https://github.com/luiskrnr/exploit-CVE-2026-23744](https://github.com/luiskrnr/exploit-CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/luiskrnr/exploit-CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/luiskrnr/exploit-CVE-2026-23744.svg)

- [https://github.com/z4yd3/PoC-CVE-2026-23744](https://github.com/z4yd3/PoC-CVE-2026-23744) :  ![starts](https://img.shields.io/github/stars/z4yd3/PoC-CVE-2026-23744.svg) ![forks](https://img.shields.io/github/forks/z4yd3/PoC-CVE-2026-23744.svg)

- [https://github.com/H1sok444/CVE-2026-23744-PoC](https://github.com/H1sok444/CVE-2026-23744-PoC) :  ![starts](https://img.shields.io/github/stars/H1sok444/CVE-2026-23744-PoC.svg) ![forks](https://img.shields.io/github/forks/H1sok444/CVE-2026-23744-PoC.svg)

- [https://github.com/suljov/CVE-2026-23744-Remote-Code-Execution-POC](https://github.com/suljov/CVE-2026-23744-Remote-Code-Execution-POC) :  ![starts](https://img.shields.io/github/stars/suljov/CVE-2026-23744-Remote-Code-Execution-POC.svg) ![forks](https://img.shields.io/github/forks/suljov/CVE-2026-23744-Remote-Code-Execution-POC.svg)

- [https://github.com/fckoo/mcpjaminspector-unauth-rce](https://github.com/fckoo/mcpjaminspector-unauth-rce) :  ![starts](https://img.shields.io/github/stars/fckoo/mcpjaminspector-unauth-rce.svg) ![forks](https://img.shields.io/github/forks/fckoo/mcpjaminspector-unauth-rce.svg)

- [https://github.com/ledksv/kobold](https://github.com/ledksv/kobold) :  ![starts](https://img.shields.io/github/stars/ledksv/kobold.svg) ![forks](https://img.shields.io/github/forks/ledksv/kobold.svg)

## CVE-2026-23723
 WeGIA is a web manager for charitable institutions. Prior to 3.6.2, an authenticated SQL Injection vulnerability was identified in the Atendido_ocorrenciaControle endpoint via the id_memorando parameter. This flaw allows for full database exfiltration, exposure of sensitive PII, and potential arbitrary file reads in misconfigured environments. This vulnerability is fixed in 3.6.2.



- [https://github.com/Ch35h1r3c47/CVE-2026-23723-POC](https://github.com/Ch35h1r3c47/CVE-2026-23723-POC) :  ![starts](https://img.shields.io/github/stars/Ch35h1r3c47/CVE-2026-23723-POC.svg) ![forks](https://img.shields.io/github/forks/Ch35h1r3c47/CVE-2026-23723-POC.svg)

## CVE-2026-23696
 Windmill CE and EE versions 1.276.0 through 1.603.2 contain an SQL injection vulnerability in the folder ownership management functionality that allows authenticated attackers to inject SQL through the owner parameter. An attacker can use the injection to read sensitive data such as the JWT signing secret and administrative user identifiers, forge an administrative token, and then execute arbitrary code via the workflow execution endpoints.



- [https://github.com/Chocapikk/Windfall](https://github.com/Chocapikk/Windfall) :  ![starts](https://img.shields.io/github/stars/Chocapikk/Windfall.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/Windfall.svg)

## CVE-2026-23552
 Cross-Realm Token Acceptance Bypass in KeycloakSecurityPolicy Apache Camel Keycloak component. 

The Camel-Keycloak KeycloakSecurityPolicy does not validate the iss (issuer) claim of JWT tokens against the configured realm. A token issued by one Keycloak realm is silently accepted by a policy configured for a completely different realm, breaking tenant isolation.
This issue affects Apache Camel: from 4.15.0 before 4.18.0.

Users are recommended to upgrade to version 4.18.0, which fixes the issue.



- [https://github.com/oscerd/CVE-2026-23552](https://github.com/oscerd/CVE-2026-23552) :  ![starts](https://img.shields.io/github/stars/oscerd/CVE-2026-23552.svg) ![forks](https://img.shields.io/github/forks/oscerd/CVE-2026-23552.svg)

## CVE-2026-23550
 Incorrect Privilege Assignment vulnerability in Modular DS Modular DS modular-connector allows Privilege Escalation.This issue affects Modular DS: from n/a through = 2.5.1.



- [https://github.com/dzmind2312/Mass-CVE-2026-23550-Exploit](https://github.com/dzmind2312/Mass-CVE-2026-23550-Exploit) :  ![starts](https://img.shields.io/github/stars/dzmind2312/Mass-CVE-2026-23550-Exploit.svg) ![forks](https://img.shields.io/github/forks/dzmind2312/Mass-CVE-2026-23550-Exploit.svg)

- [https://github.com/O99099O/By-Poloss..-..CVE-2026-23550](https://github.com/O99099O/By-Poloss..-..CVE-2026-23550) :  ![starts](https://img.shields.io/github/stars/O99099O/By-Poloss..-..CVE-2026-23550.svg) ![forks](https://img.shields.io/github/forks/O99099O/By-Poloss..-..CVE-2026-23550.svg)

- [https://github.com/DedsecTeam-BlackHat/CVE-2026-23550](https://github.com/DedsecTeam-BlackHat/CVE-2026-23550) :  ![starts](https://img.shields.io/github/stars/DedsecTeam-BlackHat/CVE-2026-23550.svg) ![forks](https://img.shields.io/github/forks/DedsecTeam-BlackHat/CVE-2026-23550.svg)

- [https://github.com/TheTorjanCaptain/CVE-2026-23550-PoC](https://github.com/TheTorjanCaptain/CVE-2026-23550-PoC) :  ![starts](https://img.shields.io/github/stars/TheTorjanCaptain/CVE-2026-23550-PoC.svg) ![forks](https://img.shields.io/github/forks/TheTorjanCaptain/CVE-2026-23550-PoC.svg)

- [https://github.com/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector) :  ![starts](https://img.shields.io/github/stars/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector.svg) ![forks](https://img.shields.io/github/forks/cyberdudebivash/CYBERDUDEBIVASH-Modular-DS-CVE-2026-23550-Detector.svg)

- [https://github.com/epsilonpoint88-glitch/EpSiLoNPoInT-](https://github.com/epsilonpoint88-glitch/EpSiLoNPoInT-) :  ![starts](https://img.shields.io/github/stars/epsilonpoint88-glitch/EpSiLoNPoInT-.svg) ![forks](https://img.shields.io/github/forks/epsilonpoint88-glitch/EpSiLoNPoInT-.svg)

## CVE-2026-23524
 Laravel Reverb provides a real-time WebSocket communication backend for Laravel applications. In versions 1.6.3 and below, Reverb passes data from the Redis channel directly into PHP’s unserialize() function without restricting which classes can be instantiated, which leaves users vulnerable to Remote Code Execution. The exploitability of this vulnerability is increased because Redis servers are commonly deployed without authentication, but only affects Laravel Reverb when horizontal scaling is enabled (REVERB_SCALING_ENABLED=true). This issue has been fixed in version 1.7.0. As a workaround, require a strong password for Redis access and ensure the service is only accessible via a private network or local loopback, and/or set REVERB_SCALING_ENABLED=false to bypass the vulnerable logic entirely (if the environment uses only one Reverb node).



- [https://github.com/rockmelodies/CVE-2026-23524](https://github.com/rockmelodies/CVE-2026-23524) :  ![starts](https://img.shields.io/github/stars/rockmelodies/CVE-2026-23524.svg) ![forks](https://img.shields.io/github/forks/rockmelodies/CVE-2026-23524.svg)

## CVE-2026-23520
 Arcane provides modern docker management. Prior to 1.13.0, Arcane has a command injection in the updater service. Arcane’s updater service supported lifecycle labels com.getarcaneapp.arcane.lifecycle.pre-update and com.getarcaneapp.arcane.lifecycle.post-update that allowed defining a command to run before or after a container update. The label value is passed directly to /bin/sh -c without sanitization or validation. Because any authenticated user (not limited to administrators) can create projects through the API, an attacker can create a project that specifies one of these lifecycle labels with a malicious command. When an administrator later triggers a container update (either manually or via scheduled update checks), Arcane reads the lifecycle label and executes its value as a shell command inside the container. This vulnerability is fixed in 1.13.0.



- [https://github.com/Augmaster/POC-CVE-2026-23520](https://github.com/Augmaster/POC-CVE-2026-23520) :  ![starts](https://img.shields.io/github/stars/Augmaster/POC-CVE-2026-23520.svg) ![forks](https://img.shields.io/github/forks/Augmaster/POC-CVE-2026-23520.svg)

- [https://github.com/cypher-21/CVE-2026-23520](https://github.com/cypher-21/CVE-2026-23520) :  ![starts](https://img.shields.io/github/stars/cypher-21/CVE-2026-23520.svg) ![forks](https://img.shields.io/github/forks/cypher-21/CVE-2026-23520.svg)

- [https://github.com/0xzap/CVE-2026-23520](https://github.com/0xzap/CVE-2026-23520) :  ![starts](https://img.shields.io/github/stars/0xzap/CVE-2026-23520.svg) ![forks](https://img.shields.io/github/forks/0xzap/CVE-2026-23520.svg)

## CVE-2026-23500
 Dolibarr is an enterprise resource planning (ERP) and customer relationship management (CRM) software package. In versions prior to 23.0.0 , the ODT to PDF conversion process in odf.php concatenates the MAIN_ODT_AS_PDF configuration constant directly into a shell command passed to exec() without sanitization. An authenticated administrator can inject arbitrary OS commands via this constant using command separators, achieving remote code execution as the web server user when any ODT template is generated. This issue has been fixed in version 23.0.0.



- [https://github.com/lukasz-rybak/CVE-2026-23500](https://github.com/lukasz-rybak/CVE-2026-23500) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-23500.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-23500.svg)

## CVE-2026-23499
 Saleor is an e-commerce platform. Starting in version 3.0.0 and prior to versions 3.20.108, 3.21.43, and 3.22.27, Saleor allowed authenticated staff users or Apps to upload arbitrary files, including malicious HTML and SVG files containing Javascript. Depending on the deployment strategy, these files may be served from the same domain as the dashboard without any restrictions leading to the execution of malicious scripts in the context of the user's browser. Malicious staff members could craft script injections to target other staff members, possibly stealing their access and/or refresh tokens. Users are vulnerable if they host the media files inside the same domain as the dashboard, e.g., dashboard is at `example.com/dashboard/` and media are under `example.com/media/`. They are not impact if media files are hosted in a different domain, e.g., `media.example.com`. Users are impacted if they do not return a `Content-Disposition: attachment` header for the media files. Saleor Cloud users are not impacted. This issue has been patched in versions: 3.22.27, 3.21.43, and 3.20.108. Some workarounds are available for those unable to upgrade. Configure the servers hosting the media files (e.g., CDN or reverse proxy) to return the Content-Disposition: attachment header. This instructs browsers to download the file instead of rendering them in the browser. Prevent the servers from returning HTML and SVG files. Set-up a `Content-Security-Policy` for media files, such as `Content-Security-Policy: default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none';`.



- [https://github.com/lukasz-rybak/CVE-2026-23499](https://github.com/lukasz-rybak/CVE-2026-23499) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-23499.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-23499.svg)

## CVE-2026-23498
 Shopware is an open commerce platform. From 6.7.0.0 to before 6.7.6.1, a regression of CVE-2023-2017 leads to an array and array crafted PHP Closure not checked being against allow list for the map(...) override. This vulnerability is fixed in 6.7.6.1.



- [https://github.com/lukasz-rybak/CVE-2026-23498](https://github.com/lukasz-rybak/CVE-2026-23498) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-23498.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-23498.svg)

## CVE-2026-23491
 InvoicePlane is a self-hosted open source application for managing invoices, clients, and payments. A path traversal vulnerability exists in the `get_file` method of the `Guest` module's `Get` controller in InvoicePlane up to and including through 1.6.3. The vulnerability allows unauthenticated attackers to read arbitrary files on the server by manipulating the input filename. This leads to the disclosure of sensitive information, including configuration files with database credentials. Version 1.6.4 fixes the issue.



- [https://github.com/lukasz-rybak/CVE-2026-23491](https://github.com/lukasz-rybak/CVE-2026-23491) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-23491.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-23491.svg)

## CVE-2026-23416
 In the Linux kernel, the following vulnerability has been resolved:

mm/mseal: update VMA end correctly on merge

Previously we stored the end of the current VMA in curr_end, and then upon
iterating to the next VMA updated curr_start to curr_end to advance to the
next VMA.

However, this doesn't take into account the fact that a VMA might be
updated due to a merge by vma_modify_flags(), which can result in curr_end
being stale and thus, upon setting curr_start to curr_end, ending up with
an incorrect curr_start on the next iteration.

Resolve the issue by setting curr_end to vma-vm_end unconditionally to
ensure this value remains updated should this occur.

While we're here, eliminate this entire class of bug by simply setting
const curr_[start/end] to be clamped to the input range and VMAs, which
also happens to simplify the logic.



- [https://github.com/bluedragonsecurity/CVE-2026-23416-POC](https://github.com/bluedragonsecurity/CVE-2026-23416-POC) :  ![starts](https://img.shields.io/github/stars/bluedragonsecurity/CVE-2026-23416-POC.svg) ![forks](https://img.shields.io/github/forks/bluedragonsecurity/CVE-2026-23416-POC.svg)

## CVE-2026-23398
 In the Linux kernel, the following vulnerability has been resolved:

icmp: fix NULL pointer dereference in icmp_tag_validation()

icmp_tag_validation() unconditionally dereferences the result of
rcu_dereference(inet_protos[proto]) without checking for NULL.
The inet_protos[] array is sparse -- only about 15 of 256 protocol
numbers have registered handlers. When ip_no_pmtu_disc is set to 3
(hardened PMTU mode) and the kernel receives an ICMP Fragmentation
Needed error with a quoted inner IP header containing an unregistered
protocol number, the NULL dereference causes a kernel panic in
softirq context.

 Oops: general protection fault, probably for non-canonical address 0xdffffc0000000002: 0000 [#1] SMP KASAN NOPTI
 KASAN: null-ptr-deref in range [0x0000000000000010-0x0000000000000017]
 RIP: 0010:icmp_unreach (net/ipv4/icmp.c:1085 net/ipv4/icmp.c:1143)
 Call Trace:
  IRQ
  icmp_rcv (net/ipv4/icmp.c:1527)
  ip_protocol_deliver_rcu (net/ipv4/ip_input.c:207)
  ip_local_deliver_finish (net/ipv4/ip_input.c:242)
  ip_local_deliver (net/ipv4/ip_input.c:262)
  ip_rcv (net/ipv4/ip_input.c:573)
  __netif_receive_skb_one_core (net/core/dev.c:6164)
  process_backlog (net/core/dev.c:6628)
  handle_softirqs (kernel/softirq.c:561)
  /IRQ

Add a NULL check before accessing icmp_strict_tag_validation. If the
protocol has no registered handler, return false since it cannot
perform strict tag validation.



- [https://github.com/JohannesLks/CVE-2026-23398](https://github.com/JohannesLks/CVE-2026-23398) :  ![starts](https://img.shields.io/github/stars/JohannesLks/CVE-2026-23398.svg) ![forks](https://img.shields.io/github/forks/JohannesLks/CVE-2026-23398.svg)

- [https://github.com/zpol/cve-2026-23398-poc](https://github.com/zpol/cve-2026-23398-poc) :  ![starts](https://img.shields.io/github/stars/zpol/cve-2026-23398-poc.svg) ![forks](https://img.shields.io/github/forks/zpol/cve-2026-23398-poc.svg)

## CVE-2026-22862
 go-ethereum (geth) is a golang execution layer implementation of the Ethereum protocol. A vulnerable node can be forced to shutdown/crash using a specially crafted message. This vulnerability is fixed in 1.16.8.



- [https://github.com/qzhodl/CVE-2026-22862](https://github.com/qzhodl/CVE-2026-22862) :  ![starts](https://img.shields.io/github/stars/qzhodl/CVE-2026-22862.svg) ![forks](https://img.shields.io/github/forks/qzhodl/CVE-2026-22862.svg)

## CVE-2026-22849
 Saleor is an e-commerce platform. Starting in version 3.0.0 and prior to versions 3.20.108, 3.21.43, and 3.22.27, Saleor was allowing users to modify rich text fields with HTML without running any backend HTML cleaners thus allowing malicious actors to perform stored XSS attacks on dashboards and storefronts. Malicious staff members could craft script injections to target other staff members, possibly stealing their access and/or refresh tokens. This issue has been patched in versions 3.22.27, 3.21.43, and 3.20.108. In case of inability to upgrade straight away, a possible workaround is to use client-side cleaner.



- [https://github.com/lukasz-rybak/CVE-2026-22849](https://github.com/lukasz-rybak/CVE-2026-22849) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-22849.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-22849.svg)

## CVE-2026-22813
 OpenCode is an open source AI coding agent. The markdown renderer used for LLM responses will insert arbitrary HTML into the DOM. There is no sanitization with DOMPurify or even a CSP on the web interface to prevent JavaScript execution via HTML injection. This means controlling the LLM response for a chat session gets JavaScript execution on the http://localhost:4096 origin. This vulnerability is fixed in 1.1.10.



- [https://github.com/HodgeLuke/ai-agent-security-research](https://github.com/HodgeLuke/ai-agent-security-research) :  ![starts](https://img.shields.io/github/stars/HodgeLuke/ai-agent-security-research.svg) ![forks](https://img.shields.io/github/forks/HodgeLuke/ai-agent-security-research.svg)

## CVE-2026-22812
 OpenCode is an open source AI coding agent. Prior to 1.0.216, OpenCode automatically starts an unauthenticated HTTP server that allows any local process (or any website via permissive CORS) to execute arbitrary shell commands with the user's privileges. This vulnerability is fixed in 1.0.216.



- [https://github.com/rohmatariow/CVE-2026-22812-exploit](https://github.com/rohmatariow/CVE-2026-22812-exploit) :  ![starts](https://img.shields.io/github/stars/rohmatariow/CVE-2026-22812-exploit.svg) ![forks](https://img.shields.io/github/forks/rohmatariow/CVE-2026-22812-exploit.svg)

- [https://github.com/barrersoftware/opencode-secure](https://github.com/barrersoftware/opencode-secure) :  ![starts](https://img.shields.io/github/stars/barrersoftware/opencode-secure.svg) ![forks](https://img.shields.io/github/forks/barrersoftware/opencode-secure.svg)

- [https://github.com/0xBlackash/CVE-2026-22812](https://github.com/0xBlackash/CVE-2026-22812) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-22812.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-22812.svg)

- [https://github.com/0xgh057r3c0n/CVE-2026-22812](https://github.com/0xgh057r3c0n/CVE-2026-22812) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2026-22812.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2026-22812.svg)

- [https://github.com/Udyz/CVE-2026-22812-Exp](https://github.com/Udyz/CVE-2026-22812-Exp) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2026-22812-Exp.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2026-22812-Exp.svg)

- [https://github.com/HodgeLuke/ai-agent-security-research](https://github.com/HodgeLuke/ai-agent-security-research) :  ![starts](https://img.shields.io/github/stars/HodgeLuke/ai-agent-security-research.svg) ![forks](https://img.shields.io/github/forks/HodgeLuke/ai-agent-security-research.svg)

- [https://github.com/mad12wader/CVE-2026-22812](https://github.com/mad12wader/CVE-2026-22812) :  ![starts](https://img.shields.io/github/stars/mad12wader/CVE-2026-22812.svg) ![forks](https://img.shields.io/github/forks/mad12wader/CVE-2026-22812.svg)

- [https://github.com/CayberMods/CVE-2026-22812-POC](https://github.com/CayberMods/CVE-2026-22812-POC) :  ![starts](https://img.shields.io/github/stars/CayberMods/CVE-2026-22812-POC.svg) ![forks](https://img.shields.io/github/forks/CayberMods/CVE-2026-22812-POC.svg)

- [https://github.com/Hex-Neo/CVE-2026-22812-OpenCode-RCE-exp](https://github.com/Hex-Neo/CVE-2026-22812-OpenCode-RCE-exp) :  ![starts](https://img.shields.io/github/stars/Hex-Neo/CVE-2026-22812-OpenCode-RCE-exp.svg) ![forks](https://img.shields.io/github/forks/Hex-Neo/CVE-2026-22812-OpenCode-RCE-exp.svg)

## CVE-2026-22807
 vLLM is an inference and serving engine for large language models (LLMs). Starting in version 0.10.1 and prior to version 0.14.0, vLLM loads Hugging Face `auto_map` dynamic modules during model resolution without gating on `trust_remote_code`, allowing attacker-controlled Python code in a model repo/path to execute at server startup. An attacker who can influence the model repo/path (local directory or remote Hugging Face repo) can achieve arbitrary code execution on the vLLM host during model load. This happens before any request handling and does not require API access. Version 0.14.0 fixes the issue.



- [https://github.com/otakuliu/CVE-2026-22807_Range](https://github.com/otakuliu/CVE-2026-22807_Range) :  ![starts](https://img.shields.io/github/stars/otakuliu/CVE-2026-22807_Range.svg) ![forks](https://img.shields.io/github/forks/otakuliu/CVE-2026-22807_Range.svg)

## CVE-2026-22804
 Termix is a web-based server management platform with SSH terminal, tunneling, and file editing capabilities. From 1.7.0 to 1.9.0, Stored Cross-Site Scripting (XSS) vulnerability exists in the Termix File Manager component. The application fails to sanitize SVG file content before rendering it. This allows an attacker who has compromised a managed SSH server to plant a malicious file, which, when previewed by the Termix user, executes arbitrary JavaScript in the context of the application. The vulnerability is located in src/ui/desktop/apps/file-manager/components/FileViewer.tsx. This vulnerability is fixed in 1.10.0.



- [https://github.com/ThemeHackers/CVE-2026-22804](https://github.com/ThemeHackers/CVE-2026-22804) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2026-22804.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2026-22804.svg)

## CVE-2026-22794
 Appsmith is a platform to build admin panels, internal tools, and dashboards. Prior to 1.93, the server uses the Origin value from the request headers as the email link baseUrl without validation. If an attacker controls the Origin, password reset / email verification links in emails can be generated pointing to the attacker’s domain, causing authentication tokens to be exposed and potentially leading to account takeover. This vulnerability is fixed in 1.93.



- [https://github.com/MalikHamza7/CVE-2026-22794-POC](https://github.com/MalikHamza7/CVE-2026-22794-POC) :  ![starts](https://img.shields.io/github/stars/MalikHamza7/CVE-2026-22794-POC.svg) ![forks](https://img.shields.io/github/forks/MalikHamza7/CVE-2026-22794-POC.svg)

## CVE-2026-22785
 orval generates type-safe JS clients (TypeScript) from any valid OpenAPI v3 or Swagger v2 specification. Prior to 7.18.0, the MCP server generation logic relies on string manipulation that incorporates the summary field from the OpenAPI specification without proper validation or escaping. This allows an attacker to "break out" of the string literal and inject arbitrary code. This vulnerability is fixed in 7.18.0.



- [https://github.com/langbyyi/CVE-2026-22785](https://github.com/langbyyi/CVE-2026-22785) :  ![starts](https://img.shields.io/github/stars/langbyyi/CVE-2026-22785.svg) ![forks](https://img.shields.io/github/forks/langbyyi/CVE-2026-22785.svg)

## CVE-2026-22777
 ComfyUI-Manager is an extension designed to enhance the usability of ComfyUI. Prior to versions 3.39.2 and 4.0.5, an attacker can inject special characters into HTTP query parameters to add arbitrary configuration values to the config.ini file. This can lead to security setting tampering or modification of application behavior. This issue has been patched in versions 3.39.2 and 4.0.5.



- [https://github.com/wcnmwcis/CVE-2026-22777](https://github.com/wcnmwcis/CVE-2026-22777) :  ![starts](https://img.shields.io/github/stars/wcnmwcis/CVE-2026-22777.svg) ![forks](https://img.shields.io/github/forks/wcnmwcis/CVE-2026-22777.svg)

## CVE-2026-22738
 In Spring AI, a SpEL injection vulnerability exists in SimpleVectorStore when a user-supplied value is used as a filter expression key. A malicious actor could exploit this to execute arbitrary code. Only applications that use SimpleVectorStore and pass user-supplied input as a filter expression key are affected.
This issue affects Spring AI: from 1.0.0 before 1.0.5, from 1.1.0 before 1.1.4.



- [https://github.com/n0n4m3x41/CVE-2026-22738-POC](https://github.com/n0n4m3x41/CVE-2026-22738-POC) :  ![starts](https://img.shields.io/github/stars/n0n4m3x41/CVE-2026-22738-POC.svg) ![forks](https://img.shields.io/github/forks/n0n4m3x41/CVE-2026-22738-POC.svg)

- [https://github.com/rockmelodies/CVE-2026-22738](https://github.com/rockmelodies/CVE-2026-22738) :  ![starts](https://img.shields.io/github/stars/rockmelodies/CVE-2026-22738.svg) ![forks](https://img.shields.io/github/forks/rockmelodies/CVE-2026-22738.svg)

## CVE-2026-22732
 When applications specify HTTP response headers for servlet applications using Spring Security, there is the possibility that the HTTP Headers will not be written. 
This issue affects Spring Security Servlet applications using lazy (default) writing of HTTP Headers:

: from 5.7.0 through 5.7.21, from 5.8.0 through 5.8.23, from 6.3.0 through 6.3.14, from 6.4.0 through 6.4.14, from 6.5.0 through 6.5.8, from 7.0.0 through 7.0.3.



- [https://github.com/semgrep/cve-2026-22732-demo](https://github.com/semgrep/cve-2026-22732-demo) :  ![starts](https://img.shields.io/github/stars/semgrep/cve-2026-22732-demo.svg) ![forks](https://img.shields.io/github/forks/semgrep/cve-2026-22732-demo.svg)

## CVE-2026-22730
 A critical SQL injection vulnerability in Spring AI's MariaDBFilterExpressionConverter allows attackers to bypass metadata-based access controls and execute arbitrary SQL commands.

The vulnerability exists due to missing input sanitization.



- [https://github.com/NULL200OK/CVE-2026-22730-Scanner](https://github.com/NULL200OK/CVE-2026-22730-Scanner) :  ![starts](https://img.shields.io/github/stars/NULL200OK/CVE-2026-22730-Scanner.svg) ![forks](https://img.shields.io/github/forks/NULL200OK/CVE-2026-22730-Scanner.svg)

## CVE-2026-22722
 A malicious actor with authenticated user privileges on a Windows based Workstation host may be able to cause a null pointer dereference error. To Remediate CVE-2026-22722, apply the patches listed in the "Fixed version" column of the 'Response Matrix'



- [https://github.com/D7EAD/CVE-2026-22722](https://github.com/D7EAD/CVE-2026-22722) :  ![starts](https://img.shields.io/github/stars/D7EAD/CVE-2026-22722.svg) ![forks](https://img.shields.io/github/forks/D7EAD/CVE-2026-22722.svg)

## CVE-2026-22692
 October is a Content Management System (CMS) and web platform. Versions prior to 3.7.13 and versions 4.0.0 through 4.1.4 contain a sandbox bypass vulnerability in the optional Twig safe mode feature (CMS_SAFE_MODE). Certain methods on the collect() helper were not properly restricted, allowing authenticated users with template editing permissions to bypass sandbox protections. Exploitation requires authenticated backend access with CMS template editing permissions and only affects installations with CMS_SAFE_MODE enabled (disabled by default). This issue has been fixed in versions 3.7.13 and 4.1.5. To workaround this issue, users can disable CMS_SAFE_MODE if untrusted template editing is not required, and restrict CMS template editing permissions to fully trusted administrators only.



- [https://github.com/lukasz-rybak/CVE-2026-22692](https://github.com/lukasz-rybak/CVE-2026-22692) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-22692.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-22692.svg)

## CVE-2026-22686
 Enclave is a secure JavaScript sandbox designed for safe AI agent code execution. Prior to 2.7.0, there is a critical sandbox escape vulnerability in enclave-vm that allows untrusted, sandboxed JavaScript code to execute arbitrary code in the host Node.js runtime. When a tool invocation fails, enclave-vm exposes a host-side Error object to sandboxed code. This Error object retains its host realm prototype chain, which can be traversed to reach the host Function constructor. An attacker can intentionally trigger a host error, then climb the prototype chain. Using the host Function constructor, arbitrary JavaScript can be compiled and executed in the host context, fully bypassing the sandbox and granting access to sensitive resources such as process.env, filesystem, and network. This breaks enclave-vm’s core security guarantee of isolating untrusted code. This vulnerability is fixed in 2.7.0.



- [https://github.com/moltengama/CVE-2026-22686-RemoteCodeExecution-RCE-PoC](https://github.com/moltengama/CVE-2026-22686-RemoteCodeExecution-RCE-PoC) :  ![starts](https://img.shields.io/github/stars/moltengama/CVE-2026-22686-RemoteCodeExecution-RCE-PoC.svg) ![forks](https://img.shields.io/github/forks/moltengama/CVE-2026-22686-RemoteCodeExecution-RCE-PoC.svg)

- [https://github.com/amusedx/CVE-2026-22686](https://github.com/amusedx/CVE-2026-22686) :  ![starts](https://img.shields.io/github/stars/amusedx/CVE-2026-22686.svg) ![forks](https://img.shields.io/github/forks/amusedx/CVE-2026-22686.svg)

## CVE-2026-22683
 Windmill versions 1.56.0 through 1.614.0 contain a missing authorization vulnerability that allows users with the Operator role to perform prohibited entity creation and modification actions via the backend API. Although Operators are documented and priced as unable to create or modify entities, the API does not enforce the Operator restriction on workspace endpoints, allowing an Operator to create and update scripts, flows, apps, and raw_apps. Since Operators can also execute scripts via the jobs API, this allows direct privilege escalation to remote code execution within the Windmill deployment. This vulnerability has existed since the introduction of the Operator role in version 1.56.0.



- [https://github.com/Chocapikk/Windfall](https://github.com/Chocapikk/Windfall) :  ![starts](https://img.shields.io/github/stars/Chocapikk/Windfall.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/Windfall.svg)

## CVE-2026-22679
 Weaver (Fanwei) E-cology 10.0 versions prior to 20260312 contain an unauthenticated remote code execution vulnerability in the /papi/esearch/data/devops/dubboApi/debug/method endpoint that allows attackers to execute arbitrary commands by invoking exposed debug functionality. Attackers can craft POST requests with attacker-controlled interfaceName and methodName parameters to reach command-execution helpers and achieve arbitrary command execution on the system. Exploitation evidence was first observed by the Shadowserver Foundation on 2026-03-31 (UTC).



- [https://github.com/keraattin/CVE-2026-22679](https://github.com/keraattin/CVE-2026-22679) :  ![starts](https://img.shields.io/github/stars/keraattin/CVE-2026-22679.svg) ![forks](https://img.shields.io/github/forks/keraattin/CVE-2026-22679.svg)

## CVE-2026-22666
 Dolibarr ERP/CRM versions prior to 23.0.2 contain an authenticated remote code execution vulnerability in the dol_eval_standard() function that fails to apply forbidden string checks in whitelist mode and does not detect PHP dynamic callable syntax. Attackers with administrator privileges can inject malicious payloads through computed extrafields or other evaluation paths using PHP dynamic callable syntax to bypass validation and achieve arbitrary command execution via eval().



- [https://github.com/JivaSecurity/DOLIBARR-RCE-CVE-2026-22666](https://github.com/JivaSecurity/DOLIBARR-RCE-CVE-2026-22666) :  ![starts](https://img.shields.io/github/stars/JivaSecurity/DOLIBARR-RCE-CVE-2026-22666.svg) ![forks](https://img.shields.io/github/forks/JivaSecurity/DOLIBARR-RCE-CVE-2026-22666.svg)

## CVE-2026-22610
 Angular is a development platform for building mobile and desktop web applications using TypeScript/JavaScript and other languages. Prior to versions 19.2.18, 20.3.16, 21.0.7, and 21.1.0-rc.0, a cross-site scripting (XSS) vulnerability has been identified in the Angular Template Compiler. The vulnerability exists because Angular’s internal sanitization schema fails to recognize the href and xlink:href attributes of SVG script elements as a Resource URL context. This issue has been patched in versions 19.2.18, 20.3.16, 21.0.7, and 21.1.0-rc.0.



- [https://github.com/ashizZz/CVE-2026-22610](https://github.com/ashizZz/CVE-2026-22610) :  ![starts](https://img.shields.io/github/stars/ashizZz/CVE-2026-22610.svg) ![forks](https://img.shields.io/github/forks/ashizZz/CVE-2026-22610.svg)

## CVE-2026-22557
 A malicious actor with access to the network could exploit a Path Traversal vulnerability found in the UniFi Network Application to access files on the underlying system that could be manipulated to access an underlying account.



- [https://github.com/0xBlackash/CVE-2026-22557](https://github.com/0xBlackash/CVE-2026-22557) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-22557.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-22557.svg)

- [https://github.com/ThePotatoOfDoom/CVE-2026-22557-PoC](https://github.com/ThePotatoOfDoom/CVE-2026-22557-PoC) :  ![starts](https://img.shields.io/github/stars/ThePotatoOfDoom/CVE-2026-22557-PoC.svg) ![forks](https://img.shields.io/github/forks/ThePotatoOfDoom/CVE-2026-22557-PoC.svg)

- [https://github.com/GarethMSheldon/cve-2026-22557-unifi-detection](https://github.com/GarethMSheldon/cve-2026-22557-unifi-detection) :  ![starts](https://img.shields.io/github/stars/GarethMSheldon/cve-2026-22557-unifi-detection.svg) ![forks](https://img.shields.io/github/forks/GarethMSheldon/cve-2026-22557-unifi-detection.svg)

## CVE-2026-22444
 The "create core" API of Apache Solr 8.6 through 9.10.0 lacks sufficient input validation on some API parameters, which can cause Solr to check the existence of and attempt to read file-system paths that should be disallowed by Solr's  "allowPaths" security setting https://https://solr.apache.org/guide/solr/latest/configuration-guide/configuring-solr-xml.html#the-solr-element .  These read-only accesses can allow users to create cores using unexpected configsets if any are accessible via the filesystem.  On Windows systems configured to allow UNC paths this can additionally cause disclosure of NTLM "user" hashes. 

Solr deployments are subject to this vulnerability if they meet the following criteria:
  *  Solr is running in its "standalone" mode.
  *  Solr's "allowPath" setting is being used to restrict file access to certain directories.
  *  Solr's "create core" API is exposed and accessible to untrusted users.  This can happen if Solr's  RuleBasedAuthorizationPlugin https://solr.apache.org/guide/solr/latest/deployment-guide/rule-based-authorization-plugin.html  is disabled, or if it is enabled but the "core-admin-edit" predefined permission (or an equivalent custom permission) is given to low-trust (i.e. non-admin) user roles.

Users can mitigate this by enabling Solr's RuleBasedAuthorizationPlugin (if disabled) and configuring a permission-list that prevents untrusted users from creating new Solr cores.  Users should also upgrade to Apache Solr 9.10.1 or greater, which contain fixes for this issue.



- [https://github.com/dptsec/CVE-2026-22444](https://github.com/dptsec/CVE-2026-22444) :  ![starts](https://img.shields.io/github/stars/dptsec/CVE-2026-22444.svg) ![forks](https://img.shields.io/github/forks/dptsec/CVE-2026-22444.svg)

- [https://github.com/bfdfhdsfdd-crypto/CVE-2026-22444](https://github.com/bfdfhdsfdd-crypto/CVE-2026-22444) :  ![starts](https://img.shields.io/github/stars/bfdfhdsfdd-crypto/CVE-2026-22444.svg) ![forks](https://img.shields.io/github/forks/bfdfhdsfdd-crypto/CVE-2026-22444.svg)

## CVE-2026-22243
 EGroupware is a Web based groupware server written in PHP. A SQL Injection vulnerability exists in the core components of EGroupware prior to versions 23.1.20260113 and 26.0.20260113, specifically in the `Nextmatch` filter processing. The flaw allows authenticated attackers to inject arbitrary SQL commands into the `WHERE` clause of database queries. This is achieved by exploiting a PHP type juggling issue where JSON decoding converts numeric strings into integers, bypassing the `is_int()` security check used by the application. Versions 23.1.20260113 and 26.0.20260113 patch the vulnerability.



- [https://github.com/lukasz-rybak/CVE-2026-22243](https://github.com/lukasz-rybak/CVE-2026-22243) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-22243.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-22243.svg)

## CVE-2026-22241
 The Open eClass platform (formerly known as GUnet eClass) is a complete course management system. Prior to version 4.2, an arbitrary file upload vulnerability in the theme import functionality enables an attacker with administrative privileges to upload arbitrary files on the server's file system. The main cause of the issue is that no validation or sanitization of the file's present inside the zip archive. This leads to remote code execution on the web server. Version 4.2 patches the issue.



- [https://github.com/0xBlackash/CVE-2026-22241](https://github.com/0xBlackash/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-22241.svg)

- [https://github.com/Ashifcoder/CVE-2026-22241](https://github.com/Ashifcoder/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/Ashifcoder/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/Ashifcoder/CVE-2026-22241.svg)

- [https://github.com/CVEs-Labs/CVE-2026-22241](https://github.com/CVEs-Labs/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/CVEs-Labs/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/CVEs-Labs/CVE-2026-22241.svg)

## CVE-2026-22200
 Enhancesoft osTicket versions 1.18.x prior to 1.18.3 and 1.17.x prior to 1.17.7 contain an arbitrary file read vulnerability in the ticket PDF export functionality. A remote attacker can submit a ticket containing crafted rich-text HTML that includes PHP filter expressions which are insufficiently sanitized before being processed by the mPDF PDF generator during export. When the attacker exports the ticket to PDF, the generated PDF can embed the contents of attacker-selected files from the server filesystem as bitmap images, allowing disclosure of sensitive local files in the context of the osTicket application user. This issue is exploitable in default configurations where guests may create tickets and access ticket status, or where self-registration is enabled.



- [https://github.com/horizon3ai/CVE-2026-22200](https://github.com/horizon3ai/CVE-2026-22200) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2026-22200.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2026-22200.svg)

- [https://github.com/Remnant-DB/CVE-2026-22200](https://github.com/Remnant-DB/CVE-2026-22200) :  ![starts](https://img.shields.io/github/stars/Remnant-DB/CVE-2026-22200.svg) ![forks](https://img.shields.io/github/forks/Remnant-DB/CVE-2026-22200.svg)

## CVE-2026-22187
 Bio-Formats versions up to and including 8.3.0 perform unsafe Java deserialization of attacker-controlled memoization cache files (.bfmemo) during image processing. The loci.formats.Memoizer class automatically loads and deserializes memo files associated with images without validation, integrity checks, or trust enforcement. An attacker who can supply a crafted .bfmemo file alongside an image can trigger deserialization of untrusted data, which may result in denial of service, logic manipulation, or potentially remote code execution in environments where suitable gadget chains are present on the classpath.



- [https://github.com/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo](https://github.com/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-22187-Bio-Formats-unsafe-Java-deserialization-via-.bfmemo.svg)

## CVE-2026-22038
 AutoGPT is a platform that allows users to create, deploy, and manage continuous artificial intelligence agents that automate complex workflows. Prior to autogpt-platform-beta-v0.6.46, the AutoGPT platform's Stagehand integration blocks log API keys and authentication secrets in plaintext using logger.info() statements. This occurs in three separate block implementations (StagehandObserveBlock, StagehandActBlock, and StagehandExtractBlock) where the code explicitly calls api_key.get_secret_value() and logs the result. This issue has been patched in autogpt-platform-beta-v0.6.46.



- [https://github.com/sivaadityacoder/CVE-2026-22038](https://github.com/sivaadityacoder/CVE-2026-22038) :  ![starts](https://img.shields.io/github/stars/sivaadityacoder/CVE-2026-22038.svg) ![forks](https://img.shields.io/github/forks/sivaadityacoder/CVE-2026-22038.svg)

## CVE-2026-21994
 Vulnerability in the Oracle Edge Cloud Infrastructure Designer and Visualisation Toolkit product of Oracle Open Source Projects (component: Desktop).   The supported version that is affected is 0.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Edge Cloud Infrastructure Designer and Visualisation Toolkit.  Successful attacks of this vulnerability can result in takeover of Oracle Edge Cloud Infrastructure Designer and Visualisation Toolkit. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).



- [https://github.com/g0w6y/CVE-2026-21994](https://github.com/g0w6y/CVE-2026-21994) :  ![starts](https://img.shields.io/github/stars/g0w6y/CVE-2026-21994.svg) ![forks](https://img.shields.io/github/forks/g0w6y/CVE-2026-21994.svg)

## CVE-2026-21986
 Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core).  Supported versions that are affected are 7.1.14 and  7.2.4. Easily exploitable vulnerability allows unauthenticated attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox.  While the vulnerability is in Oracle VM VirtualBox, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle VM VirtualBox. Note: This vulnerability applies to Windows VMs only. CVSS 3.1 Base Score 7.1 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H).



- [https://github.com/MohaBars/CVE-2026-21986-VirtualBox-DoS](https://github.com/MohaBars/CVE-2026-21986-VirtualBox-DoS) :  ![starts](https://img.shields.io/github/stars/MohaBars/CVE-2026-21986-VirtualBox-DoS.svg) ![forks](https://img.shields.io/github/forks/MohaBars/CVE-2026-21986-VirtualBox-DoS.svg)

## CVE-2026-21962
 Vulnerability in the Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in product of Oracle Fusion Middleware (component: Weblogic Server Proxy Plug-in for Apache HTTP Server, Weblogic Server Proxy Plug-in for IIS).  Supported versions that are affected are 12.2.1.4.0, 14.1.1.0.0 and  14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in.  While the vulnerability is in Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data as well as  unauthorized access to critical data or complete access to all Oracle HTTP Server, Oracle Weblogic Server Proxy Plug-in accessible data. Note: Affected version for Weblogic Server Proxy Plug-in for IIS is 12.2.1.4.0 only. CVSS 3.1 Base Score 10.0 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).



- [https://github.com/boroeurnprach/Ashwesker-CVE-2026-21962](https://github.com/boroeurnprach/Ashwesker-CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/Ashwesker-CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/Ashwesker-CVE-2026-21962.svg)

- [https://github.com/ThumpBo/CVE-2026-21962](https://github.com/ThumpBo/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/ThumpBo/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/ThumpBo/CVE-2026-21962.svg)

- [https://github.com/samael0x4/CVE-2026-21962](https://github.com/samael0x4/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/samael0x4/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/samael0x4/CVE-2026-21962.svg)

- [https://github.com/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-](https://github.com/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-21962-Oracle-HTTP-Server-WebLogic-Proxy-Plug-in-Critical-.svg)

- [https://github.com/gglessner/cve_2026_21962_scanner](https://github.com/gglessner/cve_2026_21962_scanner) :  ![starts](https://img.shields.io/github/stars/gglessner/cve_2026_21962_scanner.svg) ![forks](https://img.shields.io/github/forks/gglessner/cve_2026_21962_scanner.svg)

- [https://github.com/naozibuhao/CVE-2026-21962_Java_GUI_Exploit_Tool](https://github.com/naozibuhao/CVE-2026-21962_Java_GUI_Exploit_Tool) :  ![starts](https://img.shields.io/github/stars/naozibuhao/CVE-2026-21962_Java_GUI_Exploit_Tool.svg) ![forks](https://img.shields.io/github/forks/naozibuhao/CVE-2026-21962_Java_GUI_Exploit_Tool.svg)

- [https://github.com/0xBlackash/CVE-2026-21962](https://github.com/0xBlackash/CVE-2026-21962) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-21962.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-21962.svg)

- [https://github.com/gregk4sec/cve-2026-21962](https://github.com/gregk4sec/cve-2026-21962) :  ![starts](https://img.shields.io/github/stars/gregk4sec/cve-2026-21962.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/cve-2026-21962.svg)

- [https://github.com/gregk4sec/CVE-2026-21962-o](https://github.com/gregk4sec/CVE-2026-21962-o) :  ![starts](https://img.shields.io/github/stars/gregk4sec/CVE-2026-21962-o.svg) ![forks](https://img.shields.io/github/forks/gregk4sec/CVE-2026-21962-o.svg)

## CVE-2026-21902
 An Incorrect Permission Assignment for Critical Resource vulnerability in the On-Box Anomaly detection framework of Juniper Networks Junos OS Evolved on PTX Series allows an unauthenticated, network-based attacker to execute code as root.

The On-Box Anomaly detection framework should only be reachable by other internal processes over the internal routing instance, but not over an externally exposed port. With the ability to access and manipulate the service to execute code as root a remote attacker can take complete control of the device.
Please note that this service is enabled by default as no specific configuration is required.

This issue affects Junos OS Evolved on PTX Series:



  *  25.4 versions before 25.4R1-S1-EVO, 25.4R2-EVO.




This issue does not affect Junos OS Evolved versions before 25.4R1-EVO.

This issue does not affect Junos OS.



- [https://github.com/watchtowrlabs/watchTowr-vs-JunosEvolved-CVE-2026-21902](https://github.com/watchtowrlabs/watchTowr-vs-JunosEvolved-CVE-2026-21902) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-JunosEvolved-CVE-2026-21902.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-JunosEvolved-CVE-2026-21902.svg)

## CVE-2026-21877
 n8n is an open source workflow automation platform. In versions 0.121.2 and below, an authenticated attacker may be able to execute malicious code using the n8n service. This could result in full compromise and can impact both self-hosted and n8n Cloud instances. This issue is fixed in version 1.121.3. Administrators can reduce exposure by disabling the Git node and limiting access for untrusted users, but upgrading to the latest version is recommended.



- [https://github.com/CVEs-Labs/CVE-2026-21877](https://github.com/CVEs-Labs/CVE-2026-21877) :  ![starts](https://img.shields.io/github/stars/CVEs-Labs/CVE-2026-21877.svg) ![forks](https://img.shields.io/github/forks/CVEs-Labs/CVE-2026-21877.svg)

- [https://github.com/monkeontheroof/cve-2026-21877-rce](https://github.com/monkeontheroof/cve-2026-21877-rce) :  ![starts](https://img.shields.io/github/stars/monkeontheroof/cve-2026-21877-rce.svg) ![forks](https://img.shields.io/github/forks/monkeontheroof/cve-2026-21877-rce.svg)

## CVE-2026-21876
 The OWASP core rule set (CRS) is a set of generic attack detection rules for use with compatible web application firewalls. Prior to versions 4.22.0 and 3.3.8, the current rule 922110 has a bug when processing multipart requests with multiple parts. When the first rule in a chain iterates over a collection (like `MULTIPART_PART_HEADERS`), the capture variables (`TX:0`, `TX:1`) get overwritten with each iteration. Only the last captured value is available to the chained rule, which means malicious charsets in earlier parts can be missed if a later part has a legitimate charset. Versions 4.22.0 and 3.3.8 patch the issue.



- [https://github.com/daytriftnewgen/CVE-2026-21876](https://github.com/daytriftnewgen/CVE-2026-21876) :  ![starts](https://img.shields.io/github/stars/daytriftnewgen/CVE-2026-21876.svg) ![forks](https://img.shields.io/github/forks/daytriftnewgen/CVE-2026-21876.svg)

- [https://github.com/Mefhika120/CVE-2026-21876](https://github.com/Mefhika120/CVE-2026-21876) :  ![starts](https://img.shields.io/github/stars/Mefhika120/CVE-2026-21876.svg) ![forks](https://img.shields.io/github/forks/Mefhika120/CVE-2026-21876.svg)

- [https://github.com/CVEs-Labs/CVE-2026-21876](https://github.com/CVEs-Labs/CVE-2026-21876) :  ![starts](https://img.shields.io/github/stars/CVEs-Labs/CVE-2026-21876.svg) ![forks](https://img.shields.io/github/forks/CVEs-Labs/CVE-2026-21876.svg)

## CVE-2026-21858
 n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.



- [https://github.com/Chocapikk/CVE-2026-21858](https://github.com/Chocapikk/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2026-21858.svg)

- [https://github.com/SystemVll/CVE-2026-21858](https://github.com/SystemVll/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2026-21858.svg)

- [https://github.com/0xBlackash/CVE-2026-21858](https://github.com/0xBlackash/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-21858.svg)

- [https://github.com/EQSTLab/CVE-2026-21858](https://github.com/EQSTLab/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-21858.svg)

- [https://github.com/sec-dojo-com/CVE-2026-21858](https://github.com/sec-dojo-com/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/sec-dojo-com/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/sec-dojo-com/CVE-2026-21858.svg)

- [https://github.com/cropnet/Ni8mare](https://github.com/cropnet/Ni8mare) :  ![starts](https://img.shields.io/github/stars/cropnet/Ni8mare.svg) ![forks](https://img.shields.io/github/forks/cropnet/Ni8mare.svg)

- [https://github.com/bgarz929/Ashwesker-CVE-2026-21858](https://github.com/bgarz929/Ashwesker-CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/bgarz929/Ashwesker-CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/bgarz929/Ashwesker-CVE-2026-21858.svg)

- [https://github.com/Alhakim88/CVE-2026-21858](https://github.com/Alhakim88/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Alhakim88/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Alhakim88/CVE-2026-21858.svg)

- [https://github.com/bamov970/CVE-2026-21858](https://github.com/bamov970/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/bamov970/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/bamov970/CVE-2026-21858.svg)

- [https://github.com/kaleth4/CVE-2026-21858](https://github.com/kaleth4/CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-21858.svg)

- [https://github.com/Bannt08/Research-CVE-2026-21858](https://github.com/Bannt08/Research-CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Bannt08/Research-CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Bannt08/Research-CVE-2026-21858.svg)

- [https://github.com/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit](https://github.com/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit) :  ![starts](https://img.shields.io/github/stars/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit.svg) ![forks](https://img.shields.io/github/forks/sastraadiwiguna-purpleeliteteaming/SASTRA-ADI-WIGUNA-CVE-2026-21858-Holistic-Audit.svg)

- [https://github.com/masterwok/PoC-CVE-2026-21858](https://github.com/masterwok/PoC-CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/masterwok/PoC-CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/masterwok/PoC-CVE-2026-21858.svg)

- [https://github.com/Yati2/Ni8mare-CVE-2026-21858](https://github.com/Yati2/Ni8mare-CVE-2026-21858) :  ![starts](https://img.shields.io/github/stars/Yati2/Ni8mare-CVE-2026-21858.svg) ![forks](https://img.shields.io/github/forks/Yati2/Ni8mare-CVE-2026-21858.svg)

## CVE-2026-21857
 REDAXO is a PHP-based content management system. Prior to version 5.20.2, authenticated users with backup permissions can read arbitrary files within the webroot via path traversal in the Backup addon's file export functionality. The Backup addon does not validate the `EXPDIR` POST parameter against the UI-generated allowlist of permitted directories. An attacker can supply relative paths containing `../` sequences (or even absolute paths inside the document root) to include any readable file in the generated `.tar.gz` archive. Version 5.20.2 fixes this issue.



- [https://github.com/lukasz-rybak/CVE-2026-21857](https://github.com/lukasz-rybak/CVE-2026-21857) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-21857.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-21857.svg)

## CVE-2026-21852
 Claude Code is an agentic coding tool. Prior to version 2.0.65, vulnerability in Claude Code's project-load flow allowed malicious repositories to exfiltrate data including Anthropic API keys before users confirmed trust. An attacker-controlled repository could include a settings file that sets ANTHROPIC_BASE_URL to an attacker-controlled endpoint and when the repository was opened, Claude Code would read the configuration and immediately issue API requests before showing the trust prompt, potentially leaking the user's API keys. Users on standard Claude Code auto-update have received this fix already. Users performing manual updates are advised to update to version 2.0.65, which contains a patch, or to the latest version.



- [https://github.com/atiilla/CVE-2026-21852-PoC](https://github.com/atiilla/CVE-2026-21852-PoC) :  ![starts](https://img.shields.io/github/stars/atiilla/CVE-2026-21852-PoC.svg) ![forks](https://img.shields.io/github/forks/atiilla/CVE-2026-21852-PoC.svg)

- [https://github.com/M0broot/CVE-Archive](https://github.com/M0broot/CVE-Archive) :  ![starts](https://img.shields.io/github/stars/M0broot/CVE-Archive.svg) ![forks](https://img.shields.io/github/forks/M0broot/CVE-Archive.svg)

- [https://github.com/TreRB/ai-ide-config-guard](https://github.com/TreRB/ai-ide-config-guard) :  ![starts](https://img.shields.io/github/stars/TreRB/ai-ide-config-guard.svg) ![forks](https://img.shields.io/github/forks/TreRB/ai-ide-config-guard.svg)

## CVE-2026-21721
 The dashboard permissions API does not verify the target dashboard scope and only checks the dashboards.permissions:* action. As a result, a user who has permission management rights on one dashboard can read and modify permissions on other dashboards. This is an organization‑internal privilege escalation.



- [https://github.com/Leonideath/Exploit-LPE-CVE-2026-21721](https://github.com/Leonideath/Exploit-LPE-CVE-2026-21721) :  ![starts](https://img.shields.io/github/stars/Leonideath/Exploit-LPE-CVE-2026-21721.svg) ![forks](https://img.shields.io/github/forks/Leonideath/Exploit-LPE-CVE-2026-21721.svg)

## CVE-2026-21717
 A flaw in V8's string hashing mechanism causes integer-like strings to be hashed to their numeric value, making hash collisions trivially predictable. By crafting a request that causes many such collisions in V8's internal string table, an attacker can significantly degrade performance of the Node.js process.

The most common trigger is any endpoint that calls `JSON.parse()` on attacker-controlled input, as JSON parsing automatically internalizes short strings into the affected hash table.

This vulnerability affects **20.x, 22.x, 24.x, and 25.x**.



- [https://github.com/dajneem23/CVE-2026-21717](https://github.com/dajneem23/CVE-2026-21717) :  ![starts](https://img.shields.io/github/stars/dajneem23/CVE-2026-21717.svg) ![forks](https://img.shields.io/github/forks/dajneem23/CVE-2026-21717.svg)

## CVE-2026-21710
 A flaw in Node.js HTTP request handling causes an uncaught `TypeError` when a request is received with a header named `__proto__` and the application accesses `req.headersDistinct`.

When this occurs, `dest["__proto__"]` resolves to `Object.prototype` rather than `undefined`, causing `.push()` to be called on a non-array. This exception is thrown synchronously inside a property getter and cannot be intercepted by `error` event listeners, meaning it cannot be handled without wrapping every `req.headersDistinct` access in a `try/catch`.

* This vulnerability affects all Node.js HTTP servers on **20.x, 22.x, 24.x, and v25.x**



- [https://github.com/dajneem23/CVE-2026-21710](https://github.com/dajneem23/CVE-2026-21710) :  ![starts](https://img.shields.io/github/stars/dajneem23/CVE-2026-21710.svg) ![forks](https://img.shields.io/github/forks/dajneem23/CVE-2026-21710.svg)

## CVE-2026-21643
 An improper neutralization of special elements used in an sql command ('sql injection') vulnerability in Fortinet FortiClientEMS 7.4.4 may allow an unauthenticated attacker to execute unauthorized code or commands via specifically crafted HTTP requests.



- [https://github.com/0xBlackash/CVE-2026-21643](https://github.com/0xBlackash/CVE-2026-21643) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-21643.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-21643.svg)

- [https://github.com/alirezac0/CVE-2026-21643](https://github.com/alirezac0/CVE-2026-21643) :  ![starts](https://img.shields.io/github/stars/alirezac0/CVE-2026-21643.svg) ![forks](https://img.shields.io/github/forks/alirezac0/CVE-2026-21643.svg)

## CVE-2026-21636
 A flaw in Node.js's permission model allows Unix Domain Socket (UDS) connections to bypass network restrictions when `--permission` is enabled. Even without `--allow-net`, attacker-controlled inputs (such as URLs or socketPath options) can connect to arbitrary local sockets via net, tls, or undici/fetch. This breaks the intended security boundary of the permission model and enables access to privileged local services, potentially leading to privilege escalation, data exposure, or local code execution.

* The issue affects users of the Node.js permission model on version v25.

In the moment of this vulnerability, network permissions (`--allow-net`) are still in the experimental phase.



- [https://github.com/Pauldechassey/CVE-2026-21636](https://github.com/Pauldechassey/CVE-2026-21636) :  ![starts](https://img.shields.io/github/stars/Pauldechassey/CVE-2026-21636.svg) ![forks](https://img.shields.io/github/forks/Pauldechassey/CVE-2026-21636.svg)

## CVE-2026-21628
 A improperly secured file management feature allows uploads of dangerous data types for unauthenticated users, leading to remote code execution.



- [https://github.com/webshellseo8/CVE-2026-21628-POC](https://github.com/webshellseo8/CVE-2026-21628-POC) :  ![starts](https://img.shields.io/github/stars/webshellseo8/CVE-2026-21628-POC.svg) ![forks](https://img.shields.io/github/forks/webshellseo8/CVE-2026-21628-POC.svg)

## CVE-2026-21627
 The vulnerability was rooted in how the Tassos Framework plugin handled specific AJAX requests through Joomla’s com_ajax entry point. Under certain conditions, internal framework functionality could be invoked without proper restriction.



- [https://github.com/yallasec/CVE-2026-21627---Tassos-Novarain-Framework-plg_system_nrframework-Exploit---Joomla](https://github.com/yallasec/CVE-2026-21627---Tassos-Novarain-Framework-plg_system_nrframework-Exploit---Joomla) :  ![starts](https://img.shields.io/github/stars/yallasec/CVE-2026-21627---Tassos-Novarain-Framework-plg_system_nrframework-Exploit---Joomla.svg) ![forks](https://img.shields.io/github/forks/yallasec/CVE-2026-21627---Tassos-Novarain-Framework-plg_system_nrframework-Exploit---Joomla.svg)

## CVE-2026-21533
 Improper privilege management in Windows Remote Desktop allows an authorized attacker to elevate privileges locally.



- [https://github.com/Pairs34/RDPVulnarableCheck](https://github.com/Pairs34/RDPVulnarableCheck) :  ![starts](https://img.shields.io/github/stars/Pairs34/RDPVulnarableCheck.svg) ![forks](https://img.shields.io/github/forks/Pairs34/RDPVulnarableCheck.svg)

- [https://github.com/jenniferreire26/CVE-2026-21533](https://github.com/jenniferreire26/CVE-2026-21533) :  ![starts](https://img.shields.io/github/stars/jenniferreire26/CVE-2026-21533.svg) ![forks](https://img.shields.io/github/forks/jenniferreire26/CVE-2026-21533.svg)

- [https://github.com/fevar54/CVE-2026-21533_Scanner.py](https://github.com/fevar54/CVE-2026-21533_Scanner.py) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-21533_Scanner.py.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-21533_Scanner.py.svg)

## CVE-2026-21531
 Deserialization of untrusted data in Azure SDK allows an unauthorized attacker to execute code over a network.



- [https://github.com/NetVanguard-cmd/CVE-2026-21531](https://github.com/NetVanguard-cmd/CVE-2026-21531) :  ![starts](https://img.shields.io/github/stars/NetVanguard-cmd/CVE-2026-21531.svg) ![forks](https://img.shields.io/github/forks/NetVanguard-cmd/CVE-2026-21531.svg)

## CVE-2026-21514
 Reliance on untrusted inputs in a security decision in Microsoft Office Word allows an unauthorized attacker to bypass a security feature locally.



- [https://github.com/ChaitanyaHaritash/CVE-2026-21514_CVE-2026-21510](https://github.com/ChaitanyaHaritash/CVE-2026-21514_CVE-2026-21510) :  ![starts](https://img.shields.io/github/stars/ChaitanyaHaritash/CVE-2026-21514_CVE-2026-21510.svg) ![forks](https://img.shields.io/github/forks/ChaitanyaHaritash/CVE-2026-21514_CVE-2026-21510.svg)

## CVE-2026-21510
 Protection mechanism failure in Windows Shell allows an unauthorized attacker to bypass a security feature over a network.



- [https://github.com/andreassudo/CVE-2026-21510-CVSS-8.8-Important-Windows-Shell-security-feature-bypass](https://github.com/andreassudo/CVE-2026-21510-CVSS-8.8-Important-Windows-Shell-security-feature-bypass) :  ![starts](https://img.shields.io/github/stars/andreassudo/CVE-2026-21510-CVSS-8.8-Important-Windows-Shell-security-feature-bypass.svg) ![forks](https://img.shields.io/github/forks/andreassudo/CVE-2026-21510-CVSS-8.8-Important-Windows-Shell-security-feature-bypass.svg)

- [https://github.com/ChaitanyaHaritash/CVE-2026-21514_CVE-2026-21510](https://github.com/ChaitanyaHaritash/CVE-2026-21514_CVE-2026-21510) :  ![starts](https://img.shields.io/github/stars/ChaitanyaHaritash/CVE-2026-21514_CVE-2026-21510.svg) ![forks](https://img.shields.io/github/forks/ChaitanyaHaritash/CVE-2026-21514_CVE-2026-21510.svg)

- [https://github.com/EpSiLoNPoInTOrI/EpSiLoNPoInTlnk](https://github.com/EpSiLoNPoInTOrI/EpSiLoNPoInTlnk) :  ![starts](https://img.shields.io/github/stars/EpSiLoNPoInTOrI/EpSiLoNPoInTlnk.svg) ![forks](https://img.shields.io/github/forks/EpSiLoNPoInTOrI/EpSiLoNPoInTlnk.svg)

## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.



- [https://github.com/gavz/CVE-2026-21509-PoC](https://github.com/gavz/CVE-2026-21509-PoC) :  ![starts](https://img.shields.io/github/stars/gavz/CVE-2026-21509-PoC.svg) ![forks](https://img.shields.io/github/forks/gavz/CVE-2026-21509-PoC.svg)

- [https://github.com/kimstars/Ashwesker-CVE-2026-21509](https://github.com/kimstars/Ashwesker-CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/kimstars/Ashwesker-CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/kimstars/Ashwesker-CVE-2026-21509.svg)

- [https://github.com/suuhm/CVE-2026-21509-handler](https://github.com/suuhm/CVE-2026-21509-handler) :  ![starts](https://img.shields.io/github/stars/suuhm/CVE-2026-21509-handler.svg) ![forks](https://img.shields.io/github/forks/suuhm/CVE-2026-21509-handler.svg)

- [https://github.com/decalage2/detect_CVE-2026-21509](https://github.com/decalage2/detect_CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/decalage2/detect_CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/decalage2/detect_CVE-2026-21509.svg)

- [https://github.com/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509](https://github.com/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-MICROSOFT-OFFICE-OLE-MANIFOLD-BYPASS-CVE-2026-21509.svg)

- [https://github.com/SimoesCTT/CTT-NFS-Vortex-RCE](https://github.com/SimoesCTT/CTT-NFS-Vortex-RCE) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-NFS-Vortex-RCE.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-NFS-Vortex-RCE.svg)

- [https://github.com/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation](https://github.com/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation) :  ![starts](https://img.shields.io/github/stars/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation.svg) ![forks](https://img.shields.io/github/forks/ksk-itdk/KSK-ITDK-CVE-2026-21509-Mitigation.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-](https://github.com/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-.svg)

- [https://github.com/YoussefMami/CVE2026_21509](https://github.com/YoussefMami/CVE2026_21509) :  ![starts](https://img.shields.io/github/stars/YoussefMami/CVE2026_21509.svg) ![forks](https://img.shields.io/github/forks/YoussefMami/CVE2026_21509.svg)

- [https://github.com/planetoid/cve-2026-21509-mitigation](https://github.com/planetoid/cve-2026-21509-mitigation) :  ![starts](https://img.shields.io/github/stars/planetoid/cve-2026-21509-mitigation.svg) ![forks](https://img.shields.io/github/forks/planetoid/cve-2026-21509-mitigation.svg)

- [https://github.com/kaizensecurity/CVE-2026-21509](https://github.com/kaizensecurity/CVE-2026-21509) :  ![starts](https://img.shields.io/github/stars/kaizensecurity/CVE-2026-21509.svg) ![forks](https://img.shields.io/github/forks/kaizensecurity/CVE-2026-21509.svg)

- [https://github.com/DameDode/CVE-2026-21509-POC](https://github.com/DameDode/CVE-2026-21509-POC) :  ![starts](https://img.shields.io/github/stars/DameDode/CVE-2026-21509-POC.svg) ![forks](https://img.shields.io/github/forks/DameDode/CVE-2026-21509-POC.svg)

## CVE-2026-21508
 Improper authentication in Windows Storage allows an authorized attacker to elevate privileges locally.



- [https://github.com/0xc4r/CVE-2026-21508_POC](https://github.com/0xc4r/CVE-2026-21508_POC) :  ![starts](https://img.shields.io/github/stars/0xc4r/CVE-2026-21508_POC.svg) ![forks](https://img.shields.io/github/forks/0xc4r/CVE-2026-21508_POC.svg)

## CVE-2026-21445
 Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to version 1.7.0.dev45, multiple critical API endpoints in Langflow are missing authentication controls. The issue allows any unauthenticated user to access sensitive user conversation data, transaction histories, and perform destructive operations including message deletion. This affects endpoints handling personal data and system operations that should require proper authorization. Version 1.7.0.dev45 contains a patch.



- [https://github.com/chinaxploiter/CVE-2026-21445-PoC](https://github.com/chinaxploiter/CVE-2026-21445-PoC) :  ![starts](https://img.shields.io/github/stars/chinaxploiter/CVE-2026-21445-PoC.svg) ![forks](https://img.shields.io/github/forks/chinaxploiter/CVE-2026-21445-PoC.svg)

## CVE-2026-21440
 AdonisJS is a TypeScript-first web framework. A Path Traversal vulnerability in AdonisJS multipart file handling may allow a remote attacker to write arbitrary files to arbitrary locations on the server filesystem. This impacts @adonisjs/bodyparser through version 10.1.1 and 11.x prerelease versions prior to 11.0.0-next.6. This issue has been patched in @adonisjs/bodyparser versions 10.1.2 and 11.0.0-next.6.



- [https://github.com/k0nnect/cve-2026-21440-writeup-poc](https://github.com/k0nnect/cve-2026-21440-writeup-poc) :  ![starts](https://img.shields.io/github/stars/k0nnect/cve-2026-21440-writeup-poc.svg) ![forks](https://img.shields.io/github/forks/k0nnect/cve-2026-21440-writeup-poc.svg)

- [https://github.com/you-ssef9/CVE-2026-21440](https://github.com/you-ssef9/CVE-2026-21440) :  ![starts](https://img.shields.io/github/stars/you-ssef9/CVE-2026-21440.svg) ![forks](https://img.shields.io/github/forks/you-ssef9/CVE-2026-21440.svg)

- [https://github.com/redpack-kr/Ashwesker-CVE-2026-21440](https://github.com/redpack-kr/Ashwesker-CVE-2026-21440) :  ![starts](https://img.shields.io/github/stars/redpack-kr/Ashwesker-CVE-2026-21440.svg) ![forks](https://img.shields.io/github/forks/redpack-kr/Ashwesker-CVE-2026-21440.svg)

- [https://github.com/TibbersV6/CVE-2026-21440-POC-EXP](https://github.com/TibbersV6/CVE-2026-21440-POC-EXP) :  ![starts](https://img.shields.io/github/stars/TibbersV6/CVE-2026-21440-POC-EXP.svg) ![forks](https://img.shields.io/github/forks/TibbersV6/CVE-2026-21440-POC-EXP.svg)

## CVE-2026-21437
 eopkg is a Solus package manager implemented in python3. In versions prior to 4.4.0, a malicious package could include files that are not tracked by `eopkg`. This requires the installation of a package from a malicious or compromised source. Files in such packages would not be shown by `lseopkg` and related tools. The issue has been fixed in v4.4.0. Users only installing packages from the Solus repositories are not affected.



- [https://github.com/osmancanvural/CVE-2026-21437](https://github.com/osmancanvural/CVE-2026-21437) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2026-21437.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2026-21437.svg)

## CVE-2026-21436
 eopkg is a Solus package manager implemented in python3. In versions prior to 4.4.0, a malicious package could escape the directory set by `--destdir`. This requires the installation of a package from a malicious or compromised source. Files in such packages would not be installed in the path given by `--destdir`, but on a different location on the host. The issue has been fixed in v4.4.0. Users only installing packages from the Solus repositories are not affected.



- [https://github.com/osmancanvural/CVE-2026-21436](https://github.com/osmancanvural/CVE-2026-21436) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2026-21436.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2026-21436.svg)

## CVE-2026-21385
 Memory corruption while using alignments for memory allocation.



- [https://github.com/automate-it0/qualcomm-vulnerability-scanner](https://github.com/automate-it0/qualcomm-vulnerability-scanner) :  ![starts](https://img.shields.io/github/stars/automate-it0/qualcomm-vulnerability-scanner.svg) ![forks](https://img.shields.io/github/forks/automate-it0/qualcomm-vulnerability-scanner.svg)

## CVE-2026-21250
 Untrusted pointer dereference in Windows HTTP.sys allows an authorized attacker to elevate privileges locally.



- [https://github.com/kaleth4/CVE-2026-21250](https://github.com/kaleth4/CVE-2026-21250) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-21250.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-21250.svg)

## CVE-2026-20963
 Deserialization of untrusted data in Microsoft Office SharePoint allows an unauthorized attacker to execute code over a network.



- [https://github.com/jenniferreire26/CVE-2026-20963](https://github.com/jenniferreire26/CVE-2026-20963) :  ![starts](https://img.shields.io/github/stars/jenniferreire26/CVE-2026-20963.svg) ![forks](https://img.shields.io/github/forks/jenniferreire26/CVE-2026-20963.svg)

## CVE-2026-20871
 Use after free in Desktop Windows Manager allows an authorized attacker to elevate privileges locally.



- [https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

## CVE-2026-20841
 Improper neutralization of special elements used in a command ('command injection') in Windows Notepad App allows an unauthorized attacker to execute code locally.



- [https://github.com/BTtea/CVE-2026-20841-PoC](https://github.com/BTtea/CVE-2026-20841-PoC) :  ![starts](https://img.shields.io/github/stars/BTtea/CVE-2026-20841-PoC.svg) ![forks](https://img.shields.io/github/forks/BTtea/CVE-2026-20841-PoC.svg)

- [https://github.com/patchpoint/CVE-2026-20841](https://github.com/patchpoint/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/patchpoint/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/patchpoint/CVE-2026-20841.svg)

- [https://github.com/atiilla/CVE-2026-20841](https://github.com/atiilla/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/atiilla/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/atiilla/CVE-2026-20841.svg)

- [https://github.com/uky007/CVE-2026-20841_notepad_analysis](https://github.com/uky007/CVE-2026-20841_notepad_analysis) :  ![starts](https://img.shields.io/github/stars/uky007/CVE-2026-20841_notepad_analysis.svg) ![forks](https://img.shields.io/github/forks/uky007/CVE-2026-20841_notepad_analysis.svg)

- [https://github.com/dogukankurnaz/CVE-2026-20841-PoC](https://github.com/dogukankurnaz/CVE-2026-20841-PoC) :  ![starts](https://img.shields.io/github/stars/dogukankurnaz/CVE-2026-20841-PoC.svg) ![forks](https://img.shields.io/github/forks/dogukankurnaz/CVE-2026-20841-PoC.svg)

- [https://github.com/tangent65536/CVE-2026-20841](https://github.com/tangent65536/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/tangent65536/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/tangent65536/CVE-2026-20841.svg)

- [https://github.com/SecureWithUmer/CVE-2026-20841](https://github.com/SecureWithUmer/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/SecureWithUmer/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/SecureWithUmer/CVE-2026-20841.svg)

- [https://github.com/hamzamalik3461/CVE-2026-20841](https://github.com/hamzamalik3461/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/hamzamalik3461/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/hamzamalik3461/CVE-2026-20841.svg)

- [https://github.com/hackfaiz/CVE-2026-20841-PoC](https://github.com/hackfaiz/CVE-2026-20841-PoC) :  ![starts](https://img.shields.io/github/stars/hackfaiz/CVE-2026-20841-PoC.svg) ![forks](https://img.shields.io/github/forks/hackfaiz/CVE-2026-20841-PoC.svg)

- [https://github.com/whiskeylab/notepad_CVE_2026_20841](https://github.com/whiskeylab/notepad_CVE_2026_20841) :  ![starts](https://img.shields.io/github/stars/whiskeylab/notepad_CVE_2026_20841.svg) ![forks](https://img.shields.io/github/forks/whiskeylab/notepad_CVE_2026_20841.svg)

- [https://github.com/RajaUzairAbdullah/CVE-2026-20841](https://github.com/RajaUzairAbdullah/CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/RajaUzairAbdullah/CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/RajaUzairAbdullah/CVE-2026-20841.svg)

- [https://github.com/404godd/CVE-2026-20841-PoC](https://github.com/404godd/CVE-2026-20841-PoC) :  ![starts](https://img.shields.io/github/stars/404godd/CVE-2026-20841-PoC.svg) ![forks](https://img.shields.io/github/forks/404godd/CVE-2026-20841-PoC.svg)

- [https://github.com/EleniChristopoulou/PoC-CVE-2026-20841](https://github.com/EleniChristopoulou/PoC-CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/EleniChristopoulou/PoC-CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/EleniChristopoulou/PoC-CVE-2026-20841.svg)

## CVE-2026-20833
 Use of a broken or risky cryptographic algorithm in Windows Kerberos allows an authorized attacker to disclose information locally.



- [https://github.com/v-jfanca/cve-2026-20833-rc4-kerberos](https://github.com/v-jfanca/cve-2026-20833-rc4-kerberos) :  ![starts](https://img.shields.io/github/stars/v-jfanca/cve-2026-20833-rc4-kerberos.svg) ![forks](https://img.shields.io/github/forks/v-jfanca/cve-2026-20833-rc4-kerberos.svg)

## CVE-2026-20820
 Heap-based buffer overflow in Windows Common Log File System Driver allows an authorized attacker to elevate privileges locally.



- [https://github.com/uname1able/CVE-2026-20820](https://github.com/uname1able/CVE-2026-20820) :  ![starts](https://img.shields.io/github/stars/uname1able/CVE-2026-20820.svg) ![forks](https://img.shields.io/github/forks/uname1able/CVE-2026-20820.svg)

## CVE-2026-20817
 Improper handling of insufficient permissions or privileges in Windows Error Reporting allows an authorized attacker to elevate privileges locally.



- [https://github.com/oxfemale/CVE-2026-20817](https://github.com/oxfemale/CVE-2026-20817) :  ![starts](https://img.shields.io/github/stars/oxfemale/CVE-2026-20817.svg) ![forks](https://img.shields.io/github/forks/oxfemale/CVE-2026-20817.svg)

## CVE-2026-20805
 Exposure of sensitive information to an unauthorized actor in Desktop Windows Manager allows an authorized attacker to disclose information locally.



- [https://github.com/fevar54/CVE-2026-20805-POC](https://github.com/fevar54/CVE-2026-20805-POC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-20805-POC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-20805-POC.svg)

- [https://github.com/Uzair-Baig0900/CVE-2026-20805-PoC](https://github.com/Uzair-Baig0900/CVE-2026-20805-PoC) :  ![starts](https://img.shields.io/github/stars/Uzair-Baig0900/CVE-2026-20805-PoC.svg) ![forks](https://img.shields.io/github/forks/Uzair-Baig0900/CVE-2026-20805-PoC.svg)

- [https://github.com/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data](https://github.com/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data) :  ![starts](https://img.shields.io/github/stars/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data.svg) ![forks](https://img.shields.io/github/forks/mrk336/Inside-CVE-2026-20805-How-a-Windows-DWM-Flaw-Exposed-Sensitive-Data.svg)

- [https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

- [https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)

## CVE-2026-20698
 The issue was addressed with improved memory handling. This issue is fixed in iOS 26.4 and iPadOS 26.4, macOS Tahoe 26.4, tvOS 26.4, visionOS 26.4, watchOS 26.4. An app may be able to cause unexpected system termination or corrupt kernel memory.



- [https://github.com/Somisomair/CVE-2026-20698-PF_ROUTE-Heap-Overflow](https://github.com/Somisomair/CVE-2026-20698-PF_ROUTE-Heap-Overflow) :  ![starts](https://img.shields.io/github/stars/Somisomair/CVE-2026-20698-PF_ROUTE-Heap-Overflow.svg) ![forks](https://img.shields.io/github/forks/Somisomair/CVE-2026-20698-PF_ROUTE-Heap-Overflow.svg)

## CVE-2026-20687
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 18.7.7 and iPadOS 18.7.7, iOS 26.4 and iPadOS 26.4, macOS Sequoia 15.7.5, macOS Tahoe 26.4, tvOS 26.4, watchOS 26.4. An app may be able to cause unexpected system termination or write kernel memory.



- [https://github.com/zeroxjf/CVE-2026-20687-AppleJPEGDriver-UAF](https://github.com/zeroxjf/CVE-2026-20687-AppleJPEGDriver-UAF) :  ![starts](https://img.shields.io/github/stars/zeroxjf/CVE-2026-20687-AppleJPEGDriver-UAF.svg) ![forks](https://img.shields.io/github/forks/zeroxjf/CVE-2026-20687-AppleJPEGDriver-UAF.svg)

- [https://github.com/enfilade-labs/CVE-2026-20687-AppleJPEGDriver-UAF](https://github.com/enfilade-labs/CVE-2026-20687-AppleJPEGDriver-UAF) :  ![starts](https://img.shields.io/github/stars/enfilade-labs/CVE-2026-20687-AppleJPEGDriver-UAF.svg) ![forks](https://img.shields.io/github/forks/enfilade-labs/CVE-2026-20687-AppleJPEGDriver-UAF.svg)

## CVE-2026-20660
 A path handling issue was addressed with improved logic. This issue is fixed in Safari 26.3, iOS 18.7.5 and iPadOS 18.7.5, iOS 26.3 and iPadOS 26.3, macOS Sequoia 15.7.5, macOS Sonoma 14.8.4, macOS Tahoe 26.3, visionOS 26.3. A remote user may be able to write arbitrary files.



- [https://github.com/retX0/CVE-2026-20660](https://github.com/retX0/CVE-2026-20660) :  ![starts](https://img.shields.io/github/stars/retX0/CVE-2026-20660.svg) ![forks](https://img.shields.io/github/forks/retX0/CVE-2026-20660.svg)

## CVE-2026-20643
 A cross-origin issue in the Navigation API was addressed with improved input validation. This issue is fixed in Background Security Improvements for iOS, iPadOS, and macOS, Safari 26.4, iOS 18.7.7 and iPadOS 18.7.7, iOS 26.4 and iPadOS 26.4, macOS Tahoe 26.4, visionOS 26.4. Processing maliciously crafted web content may bypass Same Origin Policy.



- [https://github.com/zeroxjf/WebKit-NavigationAPI-SOP-Bypass](https://github.com/zeroxjf/WebKit-NavigationAPI-SOP-Bypass) :  ![starts](https://img.shields.io/github/stars/zeroxjf/WebKit-NavigationAPI-SOP-Bypass.svg) ![forks](https://img.shields.io/github/forks/zeroxjf/WebKit-NavigationAPI-SOP-Bypass.svg)

- [https://github.com/Fliv/CVE-2026-20643](https://github.com/Fliv/CVE-2026-20643) :  ![starts](https://img.shields.io/github/stars/Fliv/CVE-2026-20643.svg) ![forks](https://img.shields.io/github/forks/Fliv/CVE-2026-20643.svg)

## CVE-2026-20637
 A use after free issue was addressed with improved memory management. This issue is fixed in iOS 18.7.7 and iPadOS 18.7.7, iOS 26.3 and iPadOS 26.3, macOS Sequoia 15.7.5, macOS Sonoma 14.8.5, macOS Tahoe 26.3, tvOS 26.3, visionOS 26.3, watchOS 26.3. An app may be able to cause unexpected system termination.



- [https://github.com/zeroxjf/CVE-2026-20637-AppleSEPKeyStore-UAF](https://github.com/zeroxjf/CVE-2026-20637-AppleSEPKeyStore-UAF) :  ![starts](https://img.shields.io/github/stars/zeroxjf/CVE-2026-20637-AppleSEPKeyStore-UAF.svg) ![forks](https://img.shields.io/github/forks/zeroxjf/CVE-2026-20637-AppleSEPKeyStore-UAF.svg)

- [https://github.com/enfilade-labs/CVE-2026-20637-AppleSEPKeyStore-UAF](https://github.com/enfilade-labs/CVE-2026-20637-AppleSEPKeyStore-UAF) :  ![starts](https://img.shields.io/github/stars/enfilade-labs/CVE-2026-20637-AppleSEPKeyStore-UAF.svg) ![forks](https://img.shields.io/github/forks/enfilade-labs/CVE-2026-20637-AppleSEPKeyStore-UAF.svg)

## CVE-2026-20404
 In Modem, there is a possible system crash due to improper input validation. This could lead to remote denial of service, if a UE has connected to a rogue base station controlled by the attacker, with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: MOLY01689248; Issue ID: MSV-4837.



- [https://github.com/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-](https://github.com/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/CVE-2026-20404-MediaTek-modem-remote-DoS-rogue-base-station-scenario-.svg)

## CVE-2026-20180
 A vulnerability in Cisco Identity Services Engine (ISE) could allow an authenticated, remote attacker to execute arbitrary commands on the underlying operating system of an affected device. To exploit this vulnerability, the attacker must have at least Read Only Admin credentials.

This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. A successful exploit could allow the attacker to obtain user-level access to the underlying operating system and then elevate privileges to&nbsp;root. In single-node ISE deployments, successful exploitation of these vulnerabilities could cause the affected ISE node to become unavailable, resulting in a denial of service (DoS) condition. In that condition, endpoints that have not already authenticated would be unable to access the network until the node is restored.



- [https://github.com/kaleth4/CVE-2026-20180](https://github.com/kaleth4/CVE-2026-20180) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-20180.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-20180.svg)

## CVE-2026-20131
 A vulnerability in the web-based management interface of Cisco Secure Firewall Management Center (FMC) Software could allow an unauthenticated, remote attacker to execute arbitrary Java code as root&nbsp;on an affected device.

This vulnerability is due to insecure deserialization of a user-supplied Java byte stream. An attacker could exploit this vulnerability by sending a crafted serialized Java object to the web-based management interface of an affected device. A successful exploit could allow the attacker to execute arbitrary code on the device and elevate privileges to root.
Note: If the FMC management interface does not have public internet access, the attack surface that is associated with this vulnerability is reduced.



- [https://github.com/sak110/CVE-2026-20131](https://github.com/sak110/CVE-2026-20131) :  ![starts](https://img.shields.io/github/stars/sak110/CVE-2026-20131.svg) ![forks](https://img.shields.io/github/forks/sak110/CVE-2026-20131.svg)

- [https://github.com/Hassan-Pouladi/Cisco-FMC-honeypot](https://github.com/Hassan-Pouladi/Cisco-FMC-honeypot) :  ![starts](https://img.shields.io/github/stars/Hassan-Pouladi/Cisco-FMC-honeypot.svg) ![forks](https://img.shields.io/github/forks/Hassan-Pouladi/Cisco-FMC-honeypot.svg)

- [https://github.com/0xBlackash/CVE-2026-20131](https://github.com/0xBlackash/CVE-2026-20131) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-20131.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-20131.svg)

- [https://github.com/p3Nt3st3r-sTAr/CVE-2026-20131-POC](https://github.com/p3Nt3st3r-sTAr/CVE-2026-20131-POC) :  ![starts](https://img.shields.io/github/stars/p3Nt3st3r-sTAr/CVE-2026-20131-POC.svg) ![forks](https://img.shields.io/github/forks/p3Nt3st3r-sTAr/CVE-2026-20131-POC.svg)

## CVE-2026-20127
 A vulnerability in the peering authentication in Cisco Catalyst SD-WAN Controller, formerly SD-WAN vSmart, and Cisco Catalyst SD-WAN Manager, formerly SD-WAN vManage, could allow an unauthenticated, remote attacker to bypass authentication and obtain administrative privileges on an affected system.

This vulnerability exists because the peering authentication mechanism in an affected system is not working properly. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to log in to an affected Cisco Catalyst SD-WAN Controller as an internal, high-privileged, non-root&nbsp;user account. Using this account, the attacker could access NETCONF, which would then allow the attacker to manipulate network configuration for the SD-WAN fabric.&nbsp;



- [https://github.com/zerozenxlabs/CVE-2026-20127---Cisco-SD-WAN-Preauth-RCE](https://github.com/zerozenxlabs/CVE-2026-20127---Cisco-SD-WAN-Preauth-RCE) :  ![starts](https://img.shields.io/github/stars/zerozenxlabs/CVE-2026-20127---Cisco-SD-WAN-Preauth-RCE.svg) ![forks](https://img.shields.io/github/forks/zerozenxlabs/CVE-2026-20127---Cisco-SD-WAN-Preauth-RCE.svg)

- [https://github.com/sfewer-r7/CVE-2026-20127](https://github.com/sfewer-r7/CVE-2026-20127) :  ![starts](https://img.shields.io/github/stars/sfewer-r7/CVE-2026-20127.svg) ![forks](https://img.shields.io/github/forks/sfewer-r7/CVE-2026-20127.svg)

- [https://github.com/BugFor-Pings/CVE-2026-20127_EXP](https://github.com/BugFor-Pings/CVE-2026-20127_EXP) :  ![starts](https://img.shields.io/github/stars/BugFor-Pings/CVE-2026-20127_EXP.svg) ![forks](https://img.shields.io/github/forks/BugFor-Pings/CVE-2026-20127_EXP.svg)

- [https://github.com/yonathanpy/CVE-2026-20127-Cisco-SD-WAN-Preauth-RCE](https://github.com/yonathanpy/CVE-2026-20127-Cisco-SD-WAN-Preauth-RCE) :  ![starts](https://img.shields.io/github/stars/yonathanpy/CVE-2026-20127-Cisco-SD-WAN-Preauth-RCE.svg) ![forks](https://img.shields.io/github/forks/yonathanpy/CVE-2026-20127-Cisco-SD-WAN-Preauth-RCE.svg)

- [https://github.com/gigachadusers/cve-2026-20127](https://github.com/gigachadusers/cve-2026-20127) :  ![starts](https://img.shields.io/github/stars/gigachadusers/cve-2026-20127.svg) ![forks](https://img.shields.io/github/forks/gigachadusers/cve-2026-20127.svg)

- [https://github.com/randeepajayasekara/CVE-2026-20127](https://github.com/randeepajayasekara/CVE-2026-20127) :  ![starts](https://img.shields.io/github/stars/randeepajayasekara/CVE-2026-20127.svg) ![forks](https://img.shields.io/github/forks/randeepajayasekara/CVE-2026-20127.svg)

- [https://github.com/abrahamsurf/sdwan-scanner-CVE-2026-20127](https://github.com/abrahamsurf/sdwan-scanner-CVE-2026-20127) :  ![starts](https://img.shields.io/github/stars/abrahamsurf/sdwan-scanner-CVE-2026-20127.svg) ![forks](https://img.shields.io/github/forks/abrahamsurf/sdwan-scanner-CVE-2026-20127.svg)

## CVE-2026-20079
 A vulnerability in the web interface of Cisco Secure Firewall Management Center (FMC) Software could allow an unauthenticated, remote attacker to bypass authentication and execute script files on an affected device to obtain root access to the underlying operating system.
 This vulnerability is due to an improper system process that is created at boot time. An attacker could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow the attacker to execute a variety of scripts and commands that allow root access to the device.



- [https://github.com/0xBlackash/CVE-2026-20079](https://github.com/0xBlackash/CVE-2026-20079) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-20079.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-20079.svg)

## CVE-2026-20045
 A vulnerability in Cisco Unified Communications Manager (Unified CM), Cisco Unified Communications Manager Session Management Edition (Unified CM SME), Cisco Unified Communications Manager IM &amp; Presence Service (Unified CM IM&amp;P), Cisco Unity Connection, and Cisco Webex Calling Dedicated Instance could allow an unauthenticated, remote attacker to execute arbitrary commands on the underlying operating system of an affected device.&nbsp;

This vulnerability is due to improper validation of user-supplied input in HTTP requests. An attacker could exploit this vulnerability by sending a sequence of crafted HTTP requests to the web-based management interface of an affected device. A successful exploit could allow the attacker to obtain user-level access to the underlying operating system and then elevate privileges to root.&nbsp;
Note: Cisco has assigned this security advisory a Security Impact Rating (SIR) of Critical rather than High as the score indicates. The reason is that exploitation of this vulnerability could result in an attacker elevating privileges to root.



- [https://github.com/dkstar11q/Ashwesker-CVE-2026-20045](https://github.com/dkstar11q/Ashwesker-CVE-2026-20045) :  ![starts](https://img.shields.io/github/stars/dkstar11q/Ashwesker-CVE-2026-20045.svg) ![forks](https://img.shields.io/github/forks/dkstar11q/Ashwesker-CVE-2026-20045.svg)

## CVE-2026-7731
 A security vulnerability has been detected in code-projects BloodBank Managing System 1.0. The affected element is an unknown function of the file get_state.php. The manipulation of the argument G_STATE_ID leads to sql injection. Remote exploitation of the attack is possible. The exploit has been disclosed publicly and may be used.



- [https://github.com/SimoesCTT/CTT-Refraction-Vortex-CVE-2026-7731-](https://github.com/SimoesCTT/CTT-Refraction-Vortex-CVE-2026-7731-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-Refraction-Vortex-CVE-2026-7731-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-Refraction-Vortex-CVE-2026-7731-.svg)

## CVE-2026-7720
 A weakness has been identified in Totolink WA300 5.2cu.7112_B20190227. The impacted element is the function setLanguageCfg of the file /cgi-bin/cstecgi.cgi of the component POST Request Handler. This manipulation of the argument langType causes command injection. Remote exploitation of the attack is possible. The exploit has been made available to the public and could be used for attacks.



- [https://github.com/davidrxchester/CVE-2026-7020](https://github.com/davidrxchester/CVE-2026-7020) :  ![starts](https://img.shields.io/github/stars/davidrxchester/CVE-2026-7020.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/CVE-2026-7020.svg)

## CVE-2026-7671
 A vulnerability has been found in CodeWise Tornet Scooter Mobile App 4.75 on iOS/Android. The impacted element is an unknown function of the file /TwoFactor. Such manipulation leads to improper restriction of excessive authentication attempts. The attack may be performed from remote. Attacks of this nature are highly complex. The exploitability is regarded as difficult. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/CaginKyr/CVE-2026-7671](https://github.com/CaginKyr/CVE-2026-7671) :  ![starts](https://img.shields.io/github/stars/CaginKyr/CVE-2026-7671.svg) ![forks](https://img.shields.io/github/forks/CaginKyr/CVE-2026-7671.svg)

## CVE-2026-7669
 A vulnerability was detected in sgl-project SGLang up to 0.5.9. Impacted is the function get_tokenizer of the file python/sglang/srt/utils/hf_transformers_utils.py of the component HuggingFace Transformer Handler. The manipulation of the argument trust_remote_code with the input False as part of Boolean results in code injection. The attack can be executed remotely. A high complexity level is associated with this attack. The exploitability is considered difficult. In get_tokenizer(), when the caller passes trust_remote_code=False and HuggingFace transformers v5 returns a TokenizersBackend instance (the generic fallback for tokenizer classes not in the registry), SGLang silently re-invokes AutoTokenizer.from_pretrained with trust_remote_code=True, overriding the caller's explicit security setting. A model repository containing a malicious tokenizer.py referenced via auto_map in tokenizer_config.json will execute arbitrary Python in the SGLang process during this second call. No log line or warning is emitted. The override affects all current SGLang versions because transformers==5.3.0 is pinned in pyproject.toml. Both tokenizer_mode="auto" and tokenizer_mode="slow" are affected. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/gouldnicholas/CVE-2026-7669-PoC](https://github.com/gouldnicholas/CVE-2026-7669-PoC) :  ![starts](https://img.shields.io/github/stars/gouldnicholas/CVE-2026-7669-PoC.svg) ![forks](https://img.shields.io/github/forks/gouldnicholas/CVE-2026-7669-PoC.svg)

## CVE-2026-7567
 The Temporary Login plugin for WordPress is vulnerable to Authentication Bypass in versions up to and including 1.0.0. This is due to improper input validation in the maybe_login_temporary_user() function, which fails to verify that the 'temp-login-token' GET parameter is a scalar string before processing it. When the parameter is supplied as an array, PHP's empty() check is bypassed and sanitize_key() returns an empty string, which is then passed as the meta_value to get_users(). WordPress ignores an empty meta_value and returns all users matching the meta_key '_temporary_login_token', allowing authentication without a valid token. This makes it possible for unauthenticated attackers to authenticate as any active temporary login user by sending a single crafted GET request.



- [https://github.com/amirhosseinjamshidi64/CVE-2026-7567-POC](https://github.com/amirhosseinjamshidi64/CVE-2026-7567-POC) :  ![starts](https://img.shields.io/github/stars/amirhosseinjamshidi64/CVE-2026-7567-POC.svg) ![forks](https://img.shields.io/github/forks/amirhosseinjamshidi64/CVE-2026-7567-POC.svg)

## CVE-2026-7482
 Ollama before 0.17.1 contains a heap out-of-bounds read vulnerability in the GGUF model loader. The /api/create endpoint accepts an attacker-supplied GGUF file in which the declared tensor offset and size exceed the file's actual length; during quantization in fs/ggml/gguf.go and server/quantization.go (WriteTo()), the server reads past the allocated heap buffer. The leaked memory contents may include environment variables, API keys, system prompts, and concurrent users' conversation data, and can be exfiltrated by uploading the resulting model artifact through the /api/push endpoint to an attacker-controlled registry. The /api/create and /api/push endpoints have no authentication in the upstream distribution. Default deployments bind to 127.0.0.1, but the documented OLLAMA_HOST=0.0.0.0 configuration is widely used in practice (large public-internet exposure observed).



- [https://github.com/0x0OZ/CVE-2026-7482-PoC](https://github.com/0x0OZ/CVE-2026-7482-PoC) :  ![starts](https://img.shields.io/github/stars/0x0OZ/CVE-2026-7482-PoC.svg) ![forks](https://img.shields.io/github/forks/0x0OZ/CVE-2026-7482-PoC.svg)

- [https://github.com/msuiche/gguf_cve2026_7482](https://github.com/msuiche/gguf_cve2026_7482) :  ![starts](https://img.shields.io/github/stars/msuiche/gguf_cve2026_7482.svg) ![forks](https://img.shields.io/github/forks/msuiche/gguf_cve2026_7482.svg)

- [https://github.com/szybnev/CVE-2026-7482](https://github.com/szybnev/CVE-2026-7482) :  ![starts](https://img.shields.io/github/stars/szybnev/CVE-2026-7482.svg) ![forks](https://img.shields.io/github/forks/szybnev/CVE-2026-7482.svg)

- [https://github.com/kaleth4/CVE-2026-7482](https://github.com/kaleth4/CVE-2026-7482) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-7482.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-7482.svg)

## CVE-2026-7458
 The User Verification by PickPlugins plugin for WordPress is vulnerable to authentication bypass in all versions up to, and including, 2.0.46. This is due to the use of a loose PHP comparison operator to validate OTP codes in the "user_verification_form_wrap_process_otpLogin" function. This makes it possible for unauthenticated attackers to log in as any user with a verified email address, such as an administrator, by submitting a "true" OTP value.



- [https://github.com/zycoder0day/CVE-2026-7458](https://github.com/zycoder0day/CVE-2026-7458) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2026-7458.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2026-7458.svg)

## CVE-2026-7411
 In Eclipse BaSyx Java Server SDK versions prior to 2.0.0-milestone-10, inadequate path normalization in the Submodel HTTP API allows an unauthenticated remote attacker to perform a path traversal attack. By supplying a maliciously crafted fileName parameter during a file upload operation, an attacker can bypass intended storage boundaries and write arbitrary files to any location on the host filesystem accessible by the Java process. This can lead to Remote Code Execution (RCE) and complete system compromise.



- [https://github.com/CryptReaper12/CVE-2026-7411](https://github.com/CryptReaper12/CVE-2026-7411) :  ![starts](https://img.shields.io/github/stars/CryptReaper12/CVE-2026-7411.svg) ![forks](https://img.shields.io/github/forks/CryptReaper12/CVE-2026-7411.svg)

## CVE-2026-7401
 A vulnerability was detected in SourceCodester CET Automated Grading System with AI Predictive Analytics 1.0. This vulnerability affects unknown code of the file /index.php?action=register of the component Registration. The manipulation of the argument student_id/full_name/section/username results in cross site scripting. The attack can be launched remotely. The exploit is now public and may be used.



- [https://github.com/Xmyronn/CVE-2026-7401-XSS](https://github.com/Xmyronn/CVE-2026-7401-XSS) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-7401-XSS.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-7401-XSS.svg)

## CVE-2026-7394
 A vulnerability was determined in SourceCodester Pizzafy Ecommerce System 1.0. Affected by this vulnerability is an unknown functionality of the file /admin/view_order.php of the component GET Parameter Handler. Executing a manipulation of the argument ID can lead to sql injection. The attack may be performed from remote. The exploit has been publicly disclosed and may be utilized.



- [https://github.com/Xmyronn/CVE-2026-7394-SQLI](https://github.com/Xmyronn/CVE-2026-7394-SQLI) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-7394-SQLI.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-7394-SQLI.svg)

## CVE-2026-7393
 A vulnerability was found in SourceCodester Pizzafy Ecommerce System 1.0. Affected is the function save_menu of the file /admin/admin_class_novo.php of the component File Extension Handler. Performing a manipulation of the argument img results in unrestricted upload. The attack is possible to be carried out remotely. The exploit has been made public and could be used.



- [https://github.com/Xmyronn/CVE-2026-7393-RCE](https://github.com/Xmyronn/CVE-2026-7393-RCE) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-7393-RCE.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-7393-RCE.svg)

## CVE-2026-7270
 An operator precedence bug in the kernel results in a scenario where a buffer overflow causes attacker-controlled data to overwrite adjacent execve(2) argument buffers.

The bug may be exploitable by an unprivileged user to obtain superuser privileges.



- [https://github.com/babyshen/freebsd-CVE-2026-7270](https://github.com/babyshen/freebsd-CVE-2026-7270) :  ![starts](https://img.shields.io/github/stars/babyshen/freebsd-CVE-2026-7270.svg) ![forks](https://img.shields.io/github/forks/babyshen/freebsd-CVE-2026-7270.svg)

## CVE-2026-7229
 A vulnerability was found in code-projects Coaching Management System 1.0. This affects an unknown function of the file /cims/modules/admin/reply.php of the component POST Handler. Performing a manipulation of the argument complaintreply results in sql injection. It is possible to initiate the attack remotely. The exploit has been made public and could be used.



- [https://github.com/Xmyronn/CVE-2026-7229-SQLI](https://github.com/Xmyronn/CVE-2026-7229-SQLI) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-7229-SQLI.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-7229-SQLI.svg)

## CVE-2026-7222
 A vulnerability was determined in code-projects Coaching Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /cims/modules/student/complaint.php of the component Complaint Form Page. This manipulation of the argument Complaint causes cross site scripting. The attack can be initiated remotely. The exploit has been publicly disclosed and may be utilized.



- [https://github.com/Xmyronn/CVE-2026-7222-XSS](https://github.com/Xmyronn/CVE-2026-7222-XSS) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-7222-XSS.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-7222-XSS.svg)

## CVE-2026-7089
 A security vulnerability has been detected in code-projects Home Service System 1.0. The impacted element is an unknown function of the file /booking.php of the component Appointment Booking. The manipulation of the argument fname/lname leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed publicly and may be used.



- [https://github.com/Xmyronn/CVE-2026-7089-XSS](https://github.com/Xmyronn/CVE-2026-7089-XSS) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-7089-XSS.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-7089-XSS.svg)

## CVE-2026-7071
 A security vulnerability has been detected in CodeAstro Online Job Portal 1.0. Affected by this vulnerability is an unknown functionality of the file /users/user-cvs/. The manipulation leads to file and directory information exposure. Remote exploitation of the attack is possible. The exploit has been disclosed publicly and may be used.



- [https://github.com/Xmyronn/CVE-2026-7071-access-Control](https://github.com/Xmyronn/CVE-2026-7071-access-Control) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-7071-access-Control.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-7071-access-Control.svg)

## CVE-2026-7028
 A security flaw has been discovered in CodeAstro Online Job Portal 1.0. The affected element is an unknown function of the file /admin/jobs-admins/delete-jobs.php of the component All Jobs Page. Performing a manipulation of the argument ID results in sql injection. The attack is possible to be carried out remotely. The exploit has been released to the public and may be used for attacks.



- [https://github.com/Xmyronn/CVE-2026-7028-SQLI](https://github.com/Xmyronn/CVE-2026-7028-SQLI) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-7028-SQLI.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-7028-SQLI.svg)

## CVE-2026-7020
 A security flaw has been discovered in Ollama up to 0.20.2. This affects the function digestToPath of the file x/imagegen/transfer/transfer.go of the component Tensor Model Transfer Handler. The manipulation of the argument digest results in path traversal. The attack may be performed from remote. This attack is characterized by high complexity. The exploitability is reported as difficult. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/davidrxchester/CVE-2026-7020](https://github.com/davidrxchester/CVE-2026-7020) :  ![starts](https://img.shields.io/github/stars/davidrxchester/CVE-2026-7020.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/CVE-2026-7020.svg)

## CVE-2026-6849
 Improper neutralization of special elements used in an OS command ('OS command injection') vulnerability in TUBITAK BILGEM Software Technologies Research Institute Pardus OS My Computer allows OS Command Injection.

This issue affects Pardus OS My Computer: from =0.7.5 before 0.8.0.



- [https://github.com/osmancanvural/CVE-2026-6849](https://github.com/osmancanvural/CVE-2026-6849) :  ![starts](https://img.shields.io/github/stars/osmancanvural/CVE-2026-6849.svg) ![forks](https://img.shields.io/github/forks/osmancanvural/CVE-2026-6849.svg)

## CVE-2026-6807
 A vulnerability in GRASSMARLIN v3.2.1 allows crafted session data to 
trigger improper handling of XML input, which may result in unintended 
exposure of sensitive information. The flaw stems from insufficient 
hardening of the XML parsing process.



- [https://github.com/SecTestAnnaQuinn/Grassmarlin-CVE-2026-6807-XXE-POC](https://github.com/SecTestAnnaQuinn/Grassmarlin-CVE-2026-6807-XXE-POC) :  ![starts](https://img.shields.io/github/stars/SecTestAnnaQuinn/Grassmarlin-CVE-2026-6807-XXE-POC.svg) ![forks](https://img.shields.io/github/forks/SecTestAnnaQuinn/Grassmarlin-CVE-2026-6807-XXE-POC.svg)

## CVE-2026-6770
 Other issue in the Storage: IndexedDB component. This vulnerability was fixed in Firefox 150, Firefox ESR 140.10, Thunderbird 150, and Thunderbird 140.10.



- [https://github.com/nightcorefan94/CVE-2026-6770](https://github.com/nightcorefan94/CVE-2026-6770) :  ![starts](https://img.shields.io/github/stars/nightcorefan94/CVE-2026-6770.svg) ![forks](https://img.shields.io/github/forks/nightcorefan94/CVE-2026-6770.svg)

## CVE-2026-6644
 A command injection vulnerability was found in the PPTP VPN Clients on the ADM. The vulnerability allows an administrative user to break out of the restricted web environment and execute arbitrary code on the underlying operating system. This occurs due to insufficient validation of user-supplied input before it is passed to a system shell. Successful exploitation allows an attacker to achieve Remote Code Execution (RCE) and fully compromise the system.
Affected products and versions include: from ADM 4.1.0 through ADM 4.3.3.RR42 as well as from ADM 5.0.0 through ADM 5.1.2.REO1.



- [https://github.com/uky007/CVE-2026-6644](https://github.com/uky007/CVE-2026-6644) :  ![starts](https://img.shields.io/github/stars/uky007/CVE-2026-6644.svg) ![forks](https://img.shields.io/github/forks/uky007/CVE-2026-6644.svg)

## CVE-2026-6643
 A stack-based buffer overflow vulnerability was found in the VPN Clients on the ADM. The issue stems from the use of unbounded sscanf() and passing user-controlled data directly to printf(). Due to the lack of PIE and Stack Canary protections, an authenticated remote attacker can exploit these to execute arbitrary code as the web server user. 
Affected products and versions include: from ADM 4.1.0 through ADM 4.3.3.RR42 as well as from ADM 5.0.0 through ADM 5.1.2.REO1.



- [https://github.com/mlgzackfly/CVE-2026-6643](https://github.com/mlgzackfly/CVE-2026-6643) :  ![starts](https://img.shields.io/github/stars/mlgzackfly/CVE-2026-6643.svg) ![forks](https://img.shields.io/github/forks/mlgzackfly/CVE-2026-6643.svg)

## CVE-2026-6508
 Origin Validation Error vulnerability in TUBITAK BILGEM Software Technologies Research Institute Liderahenk allows Accessing Functionality Not Properly Constrained by ACLs.

This issue affects Liderahenk: from 2.0.1 before 2.0.2.



- [https://github.com/jackalkarlos/EvilAhenk](https://github.com/jackalkarlos/EvilAhenk) :  ![starts](https://img.shields.io/github/stars/jackalkarlos/EvilAhenk.svg) ![forks](https://img.shields.io/github/forks/jackalkarlos/EvilAhenk.svg)

## CVE-2026-6356
 A vulnerability in the web application allows standard users to escalate their privileges to those of a super administrator through parameter manipulation, enabling them to access and modify sensitive information.



- [https://github.com/Penguinsecq/CVE-2026-6355](https://github.com/Penguinsecq/CVE-2026-6355) :  ![starts](https://img.shields.io/github/stars/Penguinsecq/CVE-2026-6355.svg) ![forks](https://img.shields.io/github/forks/Penguinsecq/CVE-2026-6355.svg)

- [https://github.com/Penguinsecq/CVE-2026-6356](https://github.com/Penguinsecq/CVE-2026-6356) :  ![starts](https://img.shields.io/github/stars/Penguinsecq/CVE-2026-6356.svg) ![forks](https://img.shields.io/github/forks/Penguinsecq/CVE-2026-6356.svg)

## CVE-2026-6355
 A vulnerability in the web application allows unauthorized users to access and manipulate sensitive data across different tenants by exploiting insecure direct object references. This could lead to unauthorized access to sensitive information and unauthorized changes to the tenant's configuration.



- [https://github.com/Penguinsecq/CVE-2026-6355](https://github.com/Penguinsecq/CVE-2026-6355) :  ![starts](https://img.shields.io/github/stars/Penguinsecq/CVE-2026-6355.svg) ![forks](https://img.shields.io/github/forks/Penguinsecq/CVE-2026-6355.svg)

## CVE-2026-6227
 The BackWPup plugin for WordPress is vulnerable to Local File Inclusion via the `block_name` parameter of the `/wp-json/backwpup/v1/getblock` REST endpoint in all versions up to, and including, 5.6.6 due to a non-recursive `str_replace()` sanitization of path traversal sequences. This makes it possible for authenticated attackers, with Administrator-level access and above, to include arbitrary PHP files on the server via crafted traversal sequences (e.g., `....//`), which can be leveraged to read sensitive files such as `wp-config.php` or achieve remote code execution in certain configurations. Administrators have the ability to grant individual users permission to handle backups, which may then allow lower-level users to exploit this vulnerability.



- [https://github.com/Pixel-DefaultBR/CVE-2026-6227](https://github.com/Pixel-DefaultBR/CVE-2026-6227) :  ![starts](https://img.shields.io/github/stars/Pixel-DefaultBR/CVE-2026-6227.svg) ![forks](https://img.shields.io/github/forks/Pixel-DefaultBR/CVE-2026-6227.svg)

## CVE-2026-6201
 A vulnerability was identified in CodeAstro Online Job Portal 1.0. The impacted element is an unknown function of the file /jobs/job-delete.php of the component Delete Job Posting Handler. Such manipulation of the argument ID leads to improper access controls. The attack can be launched remotely. The exploit is publicly available and might be used.



- [https://github.com/Xmyronn/CVE-2026-6201-IDOR](https://github.com/Xmyronn/CVE-2026-6201-IDOR) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-6201-IDOR.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-6201-IDOR.svg)

## CVE-2026-6184
 A weakness has been identified in code-projects Simple Content Management System 1.0. This affects an unknown part of the file /web/admin/welcome.php. Executing a manipulation of the argument News Title can lead to cross site scripting. The attack can be executed remotely. The exploit has been made available to the public and could be used for attacks.



- [https://github.com/Xmyronn/CVE-2026-6184-stored-XSS](https://github.com/Xmyronn/CVE-2026-6184-stored-XSS) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-6184-stored-XSS.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-6184-stored-XSS.svg)

## CVE-2026-6183
 A security flaw has been discovered in code-projects Simple Content Management System 1.0. Affected by this issue is some unknown functionality of the file /web/index.php. Performing a manipulation of the argument ID results in sql injection. Remote exploitation of the attack is possible. The exploit has been released to the public and may be used for attacks.



- [https://github.com/Xmyronn/CVE-2026-6183-SQLI](https://github.com/Xmyronn/CVE-2026-6183-SQLI) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-6183-SQLI.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-6183-SQLI.svg)

## CVE-2026-6182
 A vulnerability was identified in code-projects Simple Content Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /web/admin/login.php. Such manipulation of the argument User leads to sql injection. The attack may be launched remotely. The exploit is publicly available and might be used.



- [https://github.com/Xmyronn/CVE-2026-6182-SQLI-auth](https://github.com/Xmyronn/CVE-2026-6182-SQLI-auth) :  ![starts](https://img.shields.io/github/stars/Xmyronn/CVE-2026-6182-SQLI-auth.svg) ![forks](https://img.shields.io/github/forks/Xmyronn/CVE-2026-6182-SQLI-auth.svg)

## CVE-2026-6111
 A security flaw has been discovered in FoundationAgents MetaGPT up to 0.8.1. This impacts the function decode_image of the file metagpt/utils/common.py. The manipulation of the argument img_url_or_b64 results in server-side request forgery. It is possible to launch the attack remotely. The exploit has been released to the public and may be used for attacks. The project was informed of the problem early through an issue report but has not responded yet.



- [https://github.com/MonsterWsr-hub/CVE-2026-6111](https://github.com/MonsterWsr-hub/CVE-2026-6111) :  ![starts](https://img.shields.io/github/stars/MonsterWsr-hub/CVE-2026-6111.svg) ![forks](https://img.shields.io/github/forks/MonsterWsr-hub/CVE-2026-6111.svg)

## CVE-2026-6043
 P4 Server versions prior to 2026.1 are configured with insecure default settings that, when exposed to untrusted networks, allow unauthenticated attackers to create arbitrary user accounts, enumerate existing users, authenticate to accounts with no password set, and access depot contents via the built-in 'remote' user. These default settings, taken together, can lead to unauthorized access to source code repositories and other managed assets. The 2026.1 release, expected in May 2026, enforces secure-by-default configurations on upgrade and new installations



- [https://github.com/flyingllama87/p4wned](https://github.com/flyingllama87/p4wned) :  ![starts](https://img.shields.io/github/stars/flyingllama87/p4wned.svg) ![forks](https://img.shields.io/github/forks/flyingllama87/p4wned.svg)

## CVE-2026-6042
 A security flaw has been discovered in musl libc up to 1.2.6. Affected is the function iconv of the file src/locale/iconv.c of the component GB18030 4-byte Decoder. Performing a manipulation results in inefficient algorithmic complexity. The attack must be initiated from a local position. To fix this issue, it is recommended to deploy a patch.



- [https://github.com/jensnesten/CVE-2026-6042-PoC](https://github.com/jensnesten/CVE-2026-6042-PoC) :  ![starts](https://img.shields.io/github/stars/jensnesten/CVE-2026-6042-PoC.svg) ![forks](https://img.shields.io/github/forks/jensnesten/CVE-2026-6042-PoC.svg)

## CVE-2026-5865
 Type Confusion in V8 in Google Chrome prior to 147.0.7727.55 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/Crihexe/v8-poc-CVE-2026-5865](https://github.com/Crihexe/v8-poc-CVE-2026-5865) :  ![starts](https://img.shields.io/github/stars/Crihexe/v8-poc-CVE-2026-5865.svg) ![forks](https://img.shields.io/github/forks/Crihexe/v8-poc-CVE-2026-5865.svg)

## CVE-2026-5760
 SGLang's reranking endpoint (/v1/rerank) achieves Remote Code Execution (RCE) when a model file containing a malcious tokenizer.chat_template is loaded, as the Jinja2 chat templates are rendered using an unsandboxed jinja2.Environment().



- [https://github.com/Stuub/SGLang-0.5.9-RCE](https://github.com/Stuub/SGLang-0.5.9-RCE) :  ![starts](https://img.shields.io/github/stars/Stuub/SGLang-0.5.9-RCE.svg) ![forks](https://img.shields.io/github/forks/Stuub/SGLang-0.5.9-RCE.svg)

## CVE-2026-5724
 The frontend gRPC server's streaming interceptor chain did not include the authorization interceptor. When a ClaimMapper and Authorizer are configured, unary RPCs enforce authentication and authorization, but the streaming AdminService/StreamWorkflowReplicationMessages endpoint accepted requests without credentials. This endpoint is registered on the same port as WorkflowService and cannot be disabled independently. An attacker with network access to the frontend port could open the replication stream without authentication. Data exfiltration is possible, but  only when a configured replication target is correctly configured and the attacker has knowledge of the cluster configuration, as the history service validates cluster IDs and peer membership before returning replication data.




Temporal Cloud is not affected.



- [https://github.com/tibrn/CVE-2026-5724](https://github.com/tibrn/CVE-2026-5724) :  ![starts](https://img.shields.io/github/stars/tibrn/CVE-2026-5724.svg) ![forks](https://img.shields.io/github/forks/tibrn/CVE-2026-5724.svg)

## CVE-2026-5718
 The Drag and Drop Multiple File Upload for Contact Form 7 plugin for WordPress is vulnerable to arbitrary file upload in versions up to, and including, 1.3.9.6. This is due to insufficient file type validation that occurs when custom blacklist types are configured, which replaces the default dangerous extension denylist instead of merging with it, and the wpcf7_antiscript_file_name() sanitization function being bypassed for filenames containing non-ASCII characters. This makes it possible for unauthenticated attackers to upload arbitrary files, such as PHP files, to the server, which can be leveraged to achieve remote code execution.



- [https://github.com/kyukazamiqq/cve-2026-5718](https://github.com/kyukazamiqq/cve-2026-5718) :  ![starts](https://img.shields.io/github/stars/kyukazamiqq/cve-2026-5718.svg) ![forks](https://img.shields.io/github/forks/kyukazamiqq/cve-2026-5718.svg)

## CVE-2026-5615
 A weakness has been identified in givanz Vvvebjs up to 2.0.5. The affected element is an unknown function of the file upload.php of the component File Upload Endpoint. This manipulation of the argument uploadAllowExtensions causes cross site scripting. Remote exploitation of the attack is possible. The exploit has been made available to the public and could be used for attacks. Patch name: 8cac22cff99b8bc701c408aa8e887fa702755336. Applying a patch is the recommended action to fix this issue. The vendor was contacted early, responded in a very professional manner and quickly released a fixed version of the affected product.



- [https://github.com/sahmsec/CVE-2026-5615](https://github.com/sahmsec/CVE-2026-5615) :  ![starts](https://img.shields.io/github/stars/sahmsec/CVE-2026-5615.svg) ![forks](https://img.shields.io/github/forks/sahmsec/CVE-2026-5615.svg)

## CVE-2026-5530
 A flaw has been found in Ollama up to 18.1. This issue affects some unknown processing of the file server/download.go of the component Model Pull API. Executing a manipulation can lead to server-side request forgery. The attack can be launched remotely. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/davidrxchester/CVE-2026-5530](https://github.com/davidrxchester/CVE-2026-5530) :  ![starts](https://img.shields.io/github/stars/davidrxchester/CVE-2026-5530.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/CVE-2026-5530.svg)

## CVE-2026-5465
 The Booking for Appointments and Events Calendar – Amelia plugin for WordPress is vulnerable to Insecure Direct Object Reference in all versions up to, and including, 2.1.3. This is due to the `UpdateProviderCommandHandler` failing to validate changes to the `externalId` field when a Provider (Employee) user updates their own profile. The `externalId` maps directly to a WordPress user ID and is passed to `wp_set_password()` and `wp_update_user()` without authorization checks. This makes it possible for authenticated attackers, with Provider-level (Employee) access and above, to take over any WordPress account — including Administrator — by injecting an arbitrary `externalId` value when updating their own provider profile.



- [https://github.com/kaleth4/CVE-2026-5465](https://github.com/kaleth4/CVE-2026-5465) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-5465.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-5465.svg)

## CVE-2026-5281
 Use after free in Dawn in Google Chrome prior to 146.0.7680.178 allowed a remote attacker who had compromised the renderer process to execute arbitrary code via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/umair-aziz025/CVE-2026-5281-Research-Toolkit](https://github.com/umair-aziz025/CVE-2026-5281-Research-Toolkit) :  ![starts](https://img.shields.io/github/stars/umair-aziz025/CVE-2026-5281-Research-Toolkit.svg) ![forks](https://img.shields.io/github/forks/umair-aziz025/CVE-2026-5281-Research-Toolkit.svg)

- [https://github.com/TheMalwareGuardian/CVE-2026-5281](https://github.com/TheMalwareGuardian/CVE-2026-5281) :  ![starts](https://img.shields.io/github/stars/TheMalwareGuardian/CVE-2026-5281.svg) ![forks](https://img.shields.io/github/forks/TheMalwareGuardian/CVE-2026-5281.svg)

## CVE-2026-5252
 A security flaw has been discovered in z-9527 admin 1.0/2.0. Affected is an unknown function of the file /server/routes/message.js of the component Message Create Endpoint. Performing a manipulation results in cross site scripting. The attack can be initiated remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/aydin5245/CVE-2026-5252-CVE-POC-ivanti](https://github.com/aydin5245/CVE-2026-5252-CVE-POC-ivanti) :  ![starts](https://img.shields.io/github/stars/aydin5245/CVE-2026-5252-CVE-POC-ivanti.svg) ![forks](https://img.shields.io/github/forks/aydin5245/CVE-2026-5252-CVE-POC-ivanti.svg)

## CVE-2026-5201
 A flaw was found in the gdk-pixbuf library. This heap-based buffer overflow vulnerability occurs in the JPEG image loader due to improper validation of color component counts when processing a specially crafted JPEG image. A remote attacker can exploit this flaw without user interaction, for example, via thumbnail generation. Successful exploitation leads to application crashes and denial of service (DoS) conditions.



- [https://github.com/kagancapar/CVE-2026-5201](https://github.com/kagancapar/CVE-2026-5201) :  ![starts](https://img.shields.io/github/stars/kagancapar/CVE-2026-5201.svg) ![forks](https://img.shields.io/github/forks/kagancapar/CVE-2026-5201.svg)

## CVE-2026-5194
 Missing hash/digest size and OID checks allow digests smaller than allowed when verifying ECDSA certificates, or smaller than is appropriate for the relevant key type, to be accepted by signature verification functions. This could lead to reduced security of ECDSA certificate-based authentication if the public CA key used is also known. This affects ECDSA/ECC verification when EdDSA or ML-DSA is also enabled.



- [https://github.com/jenniferreire26/CVE-2026-5194](https://github.com/jenniferreire26/CVE-2026-5194) :  ![starts](https://img.shields.io/github/stars/jenniferreire26/CVE-2026-5194.svg) ![forks](https://img.shields.io/github/forks/jenniferreire26/CVE-2026-5194.svg)

## CVE-2026-5173
 GitLab has remediated an issue in GitLab CE/EE affecting all versions from 16.9.6 before 18.8.9, 18.9 before 18.9.5, and 18.10 before 18.10.3 that could have allowed an authenticated user to invoke unintended server-side methods through websocket connections due to improper access control.



- [https://github.com/0xBlackash/CVE-2026-5173](https://github.com/0xBlackash/CVE-2026-5173) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-5173.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-5173.svg)

## CVE-2026-5147
 A security flaw has been discovered in YunaiV yudao-cloud up to 2026.01. This affects an unknown part of the file /admin-api/system/tenant/get-by-website. The manipulation of the argument Website results in sql injection. It is possible to launch the attack remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/lan1oc/cve-2026-5147-exp](https://github.com/lan1oc/cve-2026-5147-exp) :  ![starts](https://img.shields.io/github/stars/lan1oc/cve-2026-5147-exp.svg) ![forks](https://img.shields.io/github/forks/lan1oc/cve-2026-5147-exp.svg)

## CVE-2026-5059
 aws-mcp-server AWS CLI Command Injection Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of aws-mcp-server. Authentication is not required to exploit this vulnerability.

The specific flaw exists within the handling of the allowed commands list. The issue results from the lack of proper validation of a user-supplied string before using it to execute a system call. An attacker can leverage this vulnerability to execute code in the context of the MCP server. Was ZDI-CAN-27969.



- [https://github.com/venom203020/CVE-2026-5059-poc](https://github.com/venom203020/CVE-2026-5059-poc) :  ![starts](https://img.shields.io/github/stars/venom203020/CVE-2026-5059-poc.svg) ![forks](https://img.shields.io/github/forks/venom203020/CVE-2026-5059-poc.svg)

## CVE-2026-5027
 The 'POST /api/v2/files' endpoint does not sanitize the 'filename' parameter from the multipart form data, allowing an attacker to write files to arbitrary locations on the filesystem using path traversal sequences ('../').



- [https://github.com/yahiahamza/CVE-2026-5027](https://github.com/yahiahamza/CVE-2026-5027) :  ![starts](https://img.shields.io/github/stars/yahiahamza/CVE-2026-5027.svg) ![forks](https://img.shields.io/github/forks/yahiahamza/CVE-2026-5027.svg)

- [https://github.com/EQSTLab/CVE-2026-5027](https://github.com/EQSTLab/CVE-2026-5027) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-5027.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-5027.svg)

- [https://github.com/0xBlackash/CVE-2026-5027](https://github.com/0xBlackash/CVE-2026-5027) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-5027.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-5027.svg)

- [https://github.com/min8282/CVE-2026-5027](https://github.com/min8282/CVE-2026-5027) :  ![starts](https://img.shields.io/github/stars/min8282/CVE-2026-5027.svg) ![forks](https://img.shields.io/github/forks/min8282/CVE-2026-5027.svg)

## CVE-2026-5000
 A vulnerability was detected in PromtEngineer localGPT up to 4d41c7d1713b16b216d8e062e51a5dd88b20b054. Impacted is the function LocalGPTHandler of the file backend/server.py of the component API Endpoint. The manipulation of the argument BaseHTTPRequestHandler results in missing authentication. The attack can be executed remotely. This product implements a rolling release for ongoing delivery, which means version information for affected or updated releases is unavailable. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/Perl-Code/CVE-2026-5000](https://github.com/Perl-Code/CVE-2026-5000) :  ![starts](https://img.shields.io/github/stars/Perl-Code/CVE-2026-5000.svg) ![forks](https://img.shields.io/github/forks/Perl-Code/CVE-2026-5000.svg)

## CVE-2026-4821
 An improper neutralization of special elements vulnerability was identified in GitHub Enterprise Server that allowed an authenticated Management Console administrator to execute arbitrary OS commands via shell metacharacter injection in proxy configuration fields such as http_proxy. Exploitation of this vulnerability required access to the GitHub Enterprise Server instance and administrator privileges to the Management Console. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.21 and was fixed in versions 3.20.1, 3.19.5, 3.18.8, 3.17.14, 3.16.17, 3.15.21, 3.14.26. This vulnerability was reported via the GitHub Bug Bounty program.



- [https://github.com/openexecution-coder/demo-cve-2026-4821](https://github.com/openexecution-coder/demo-cve-2026-4821) :  ![starts](https://img.shields.io/github/stars/openexecution-coder/demo-cve-2026-4821.svg) ![forks](https://img.shields.io/github/forks/openexecution-coder/demo-cve-2026-4821.svg)

- [https://github.com/isagoakira/ghes-cve-scanner](https://github.com/isagoakira/ghes-cve-scanner) :  ![starts](https://img.shields.io/github/stars/isagoakira/ghes-cve-scanner.svg) ![forks](https://img.shields.io/github/forks/isagoakira/ghes-cve-scanner.svg)

## CVE-2026-4800
 Impact:

The fix for CVE-2021-23337 (https://github.com/advisories/GHSA-35jh-r3h4-6jhm) added validation for the variable option in _.template but did not apply the same validation to options.imports key names. Both paths flow into the same Function() constructor sink.

When an application passes untrusted input as options.imports key names, an attacker can inject default-parameter expressions that execute arbitrary code at template compilation time.

Additionally, _.template uses assignInWith to merge imports, which enumerates inherited properties via for..in. If Object.prototype has been polluted by any other vector, the polluted keys are copied into the imports object and passed to Function().

Patches:

Users should upgrade to version 4.18.0.

Workarounds:

Do not pass untrusted input as key names in options.imports. Only use developer-controlled, static key names.



- [https://github.com/threalwinky/CVE-2026-4800-POC](https://github.com/threalwinky/CVE-2026-4800-POC) :  ![starts](https://img.shields.io/github/stars/threalwinky/CVE-2026-4800-POC.svg) ![forks](https://img.shields.io/github/forks/threalwinky/CVE-2026-4800-POC.svg)

- [https://github.com/SvenLie/next-rep-CVE-2026-4800](https://github.com/SvenLie/next-rep-CVE-2026-4800) :  ![starts](https://img.shields.io/github/stars/SvenLie/next-rep-CVE-2026-4800.svg) ![forks](https://img.shields.io/github/forks/SvenLie/next-rep-CVE-2026-4800.svg)

## CVE-2026-4747
 Each RPCSEC_GSS data packet is validated by a routine which checks a signature in the packet.  This routine copies a portion of the packet into a stack buffer, but fails to ensure that the buffer is sufficiently large, and a malicious client can trigger a stack overflow.  Notably, this does not require the client to authenticate itself first.

As kgssapi.ko's RPCSEC_GSS implementation is vulnerable, remote code execution in the kernel is possible by an authenticated user that is able to send packets to the kernel's NFS server while kgssapi.ko is loaded into the kernel.

In userspace, applications which have librpcgss_sec loaded and run an RPC server are vulnerable to remote code execution from any client able to send it packets.  We are not aware of any such applications in the FreeBSD base system.



- [https://github.com/kaleth4/CVE-2026-4747-](https://github.com/kaleth4/CVE-2026-4747-) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-4747-.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-4747-.svg)

- [https://github.com/kaleth4/CVE-2026-4747](https://github.com/kaleth4/CVE-2026-4747) :  ![starts](https://img.shields.io/github/stars/kaleth4/CVE-2026-4747.svg) ![forks](https://img.shields.io/github/forks/kaleth4/CVE-2026-4747.svg)

## CVE-2026-4660
 HashiCorp’s go-getter library up to v1.8.5 may allow arbitrary file reads on the file system during certain git operations through a maliciously crafted URL. This vulnerability, CVE-2026-4660, is fixed in go-getter v1.8.6. This vulnerability does not affect the go-getter/v2 branch and package.



- [https://github.com/gouldnicholas/CVE-2026-4660-PoC](https://github.com/gouldnicholas/CVE-2026-4660-PoC) :  ![starts](https://img.shields.io/github/stars/gouldnicholas/CVE-2026-4660-PoC.svg) ![forks](https://img.shields.io/github/forks/gouldnicholas/CVE-2026-4660-PoC.svg)

## CVE-2026-4631
 Cockpit's remote login feature passes user-supplied hostnames and usernames from the web interface to the SSH client without validation or sanitization. An attacker with network access to the Cockpit web service can craft a single HTTP request to the login endpoint that injects malicious SSH options or shell commands, achieving code execution on the Cockpit host without valid credentials. The injection occurs during the authentication flow before any credential verification takes place, meaning no login is required to exploit the vulnerability.



- [https://github.com/cyberheartmi9/CVE-2026-4631-cockpit-RCE](https://github.com/cyberheartmi9/CVE-2026-4631-cockpit-RCE) :  ![starts](https://img.shields.io/github/stars/cyberheartmi9/CVE-2026-4631-cockpit-RCE.svg) ![forks](https://img.shields.io/github/forks/cyberheartmi9/CVE-2026-4631-cockpit-RCE.svg)

## CVE-2026-4484
 The Masteriyo LMS plugin for WordPress is vulnerable to Privilege Escalation in all versions up to, and including, 2.1.6. This is due to the plugin allowing a user to update the user role through the 'InstructorsController::prepare_object_for_database' function. This makes it possible for authenticated attackers, with Student-level access and above, to elevate their privileges to that of an administrator.



- [https://github.com/Nxploited/CVE-2026-4484](https://github.com/Nxploited/CVE-2026-4484) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-4484.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-4484.svg)

## CVE-2026-4464
 Integer overflow in ANGLE in Google Chrome prior to 146.0.7680.153 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)



- [https://github.com/zzzm0919/CVE-2026-44648](https://github.com/zzzm0919/CVE-2026-44648) :  ![starts](https://img.shields.io/github/stars/zzzm0919/CVE-2026-44648.svg) ![forks](https://img.shields.io/github/forks/zzzm0919/CVE-2026-44648.svg)

## CVE-2026-4459
 Out of bounds read and write in WebAudio in Google Chrome prior to 146.0.7680.153 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/Astaruf/CVE-2026-44590](https://github.com/Astaruf/CVE-2026-44590) :  ![starts](https://img.shields.io/github/stars/Astaruf/CVE-2026-44590.svg) ![forks](https://img.shields.io/github/forks/Astaruf/CVE-2026-44590.svg)

## CVE-2026-4447
 Inappropriate implementation in V8 in Google Chrome prior to 146.0.7680.153 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/NetVanguard-cmd/CVE-2026-4447](https://github.com/NetVanguard-cmd/CVE-2026-4447) :  ![starts](https://img.shields.io/github/stars/NetVanguard-cmd/CVE-2026-4447.svg) ![forks](https://img.shields.io/github/forks/NetVanguard-cmd/CVE-2026-4447.svg)

## CVE-2026-4426
 A flaw was found in libarchive. An Undefined Behavior vulnerability exists in the zisofs decompression logic, caused by improper validation of a field (`pz_log2_bs`) read from ISO9660 Rock Ridge extensions. A remote attacker can exploit this by supplying a specially crafted ISO file. This can lead to incorrect memory allocation and potential application crashes, resulting in a denial-of-service (DoS) condition.



- [https://github.com/joshuavanderpoll/CVE-2026-44262](https://github.com/joshuavanderpoll/CVE-2026-44262) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2026-44262.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2026-44262.svg)

## CVE-2026-4406
 The Gravity Forms plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the `form_ids` parameter in the `gform_get_config` AJAX action in all versions up to, and including, 2.9.30. This is due to the `GFCommon::send_json()` method outputting JSON-encoded data wrapped in HTML comment delimiters using `echo` and `wp_die()`, which serves the response with a `Content-Type: text/html` header instead of `application/json`. The `wp_json_encode()` function does not HTML-encode angle brackets within JSON string values, allowing injected HTML/script tags in `form_ids` array values to be parsed and executed by the browser. The required `config_nonce` is generated with `wp_create_nonce('gform_config_ajax')` and is publicly embedded on every page that renders a Gravity Forms form, making it identical for all unauthenticated visitors within the same 12-hour nonce tick. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link. This vulnerability cannot be exploited against users who are authenticated on the target system, but could be used to alter the target page.



- [https://github.com/Hann1bl3L3ct3r/CVE-2026-4406](https://github.com/Hann1bl3L3ct3r/CVE-2026-4406) :  ![starts](https://img.shields.io/github/stars/Hann1bl3L3ct3r/CVE-2026-4406.svg) ![forks](https://img.shields.io/github/forks/Hann1bl3L3ct3r/CVE-2026-4406.svg)

## CVE-2026-4389
 The DSGVO snippet for Leaflet Map and its Extensions plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the `leafext-cookie-time` and `leafext-delete-cookie` shortcodes in all versions up to, and including, 3.1. This is due to insufficient input sanitization and output escaping on user supplied attributes (`unset`, `before`, `after`). This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/Dobby153/CVE-2026-43893](https://github.com/Dobby153/CVE-2026-43893) :  ![starts](https://img.shields.io/github/stars/Dobby153/CVE-2026-43893.svg) ![forks](https://img.shields.io/github/forks/Dobby153/CVE-2026-43893.svg)

## CVE-2026-4350
 The Perfmatters plugin for WordPress is vulnerable to arbitrary file deletion via path traversal in all versions up to, and including, 2.5.9.1. This is due to the `PMCS::action_handler()` method processing the `$_GET['delete']` parameter without any sanitization, authorization check, or nonce verification. The unsanitized filename is concatenated with the storage directory path and passed to `unlink()`. This makes it possible for authenticated attackers, with Subscriber-level access and above, to delete arbitrary files on the server by using `../` path traversal sequences, including `wp-config.php` which would force WordPress into the installation wizard and allow full site takeover.



- [https://github.com/whyiamsobusy/CVE-2026-4350](https://github.com/whyiamsobusy/CVE-2026-4350) :  ![starts](https://img.shields.io/github/stars/whyiamsobusy/CVE-2026-4350.svg) ![forks](https://img.shields.io/github/forks/whyiamsobusy/CVE-2026-4350.svg)

- [https://github.com/attaattaatta/CVE-2026-43500](https://github.com/attaattaatta/CVE-2026-43500) :  ![starts](https://img.shields.io/github/stars/attaattaatta/CVE-2026-43500.svg) ![forks](https://img.shields.io/github/forks/attaattaatta/CVE-2026-43500.svg)

## CVE-2026-4342
 A security issue was discovered in ingress-nginx where a combination of Ingress annotations can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)



- [https://github.com/stuartMoorhouse/CVE-2026-4342](https://github.com/stuartMoorhouse/CVE-2026-4342) :  ![starts](https://img.shields.io/github/stars/stuartMoorhouse/CVE-2026-4342.svg) ![forks](https://img.shields.io/github/forks/stuartMoorhouse/CVE-2026-4342.svg)

## CVE-2026-4287
 A security flaw has been discovered in Tiandy Easy7 Integrated Management Platform 7.17.0. The affected element is an unknown function of the file /rest/devStatus/queryResources of the component Endpoint. Performing a manipulation of the argument areaId results in sql injection. The attack can be initiated remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/guzrex/CVE-2026-42879](https://github.com/guzrex/CVE-2026-42879) :  ![starts](https://img.shields.io/github/stars/guzrex/CVE-2026-42879.svg) ![forks](https://img.shields.io/github/forks/guzrex/CVE-2026-42879.svg)

## CVE-2026-4257
 The Contact Form by Supsystic plugin for WordPress is vulnerable to Server-Side Template Injection (SSTI) leading to Remote Code Execution (RCE) in all versions up to, and including, 1.7.36. This is due to the plugin using the Twig `Twig_Loader_String` template engine without sandboxing, combined with the `cfsPreFill` prefill functionality that allows unauthenticated users to inject arbitrary Twig expressions into form field values via GET parameters. This makes it possible for unauthenticated attackers to execute arbitrary PHP functions and OS commands on the server by leveraging Twig's `registerUndefinedFilterCallback()` method to register arbitrary PHP callbacks.



- [https://github.com/bootstrapbool/cve-2026-4257](https://github.com/bootstrapbool/cve-2026-4257) :  ![starts](https://img.shields.io/github/stars/bootstrapbool/cve-2026-4257.svg) ![forks](https://img.shields.io/github/forks/bootstrapbool/cve-2026-4257.svg)

## CVE-2026-4228
 A vulnerability was detected in LB-LINK BL-WR9000 2.4.9. This affects the function sub_458754 of the file /goform/set_wifi. The manipulation results in command injection. It is possible to launch the attack remotely. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/Astaruf/CVE-2026-42281](https://github.com/Astaruf/CVE-2026-42281) :  ![starts](https://img.shields.io/github/stars/Astaruf/CVE-2026-42281.svg) ![forks](https://img.shields.io/github/forks/Astaruf/CVE-2026-42281.svg)

## CVE-2026-4214
 A flaw has been found in D-Link DNS-120, DNR-202L, DNS-315L, DNS-320, DNS-320L, DNS-320LW, DNS-321, DNR-322L, DNS-323, DNS-325, DNS-326, DNS-327L, DNR-326, DNS-340L, DNS-343, DNS-345, DNS-726-4, DNS-1100-4, DNS-1200-05 and DNS-1550-04 up to 20260205. This issue affects the function UPnP_AV_Server_Path_Setting of the file /cgi-bin/app_mgr.cgi. Executing a manipulation can lead to stack-based buffer overflow. The attack may be launched remotely. The exploit has been published and may be used.



- [https://github.com/H4zaz/CVE-2026-42141-xibo-ssrf](https://github.com/H4zaz/CVE-2026-42141-xibo-ssrf) :  ![starts](https://img.shields.io/github/stars/H4zaz/CVE-2026-42141-xibo-ssrf.svg) ![forks](https://img.shields.io/github/forks/H4zaz/CVE-2026-42141-xibo-ssrf.svg)

## CVE-2026-4112
 Improper neutralization of special elements used in an SQL command (“SQL Injection”) in SonicWall SMA1000 series appliances allows a remote authenticated attacker with read-only administrator privileges to escalate privileges to primary administrator.



- [https://github.com/Hann1bl3L3ct3r/CVE-2026-4112](https://github.com/Hann1bl3L3ct3r/CVE-2026-4112) :  ![starts](https://img.shields.io/github/stars/Hann1bl3L3ct3r/CVE-2026-4112.svg) ![forks](https://img.shields.io/github/forks/Hann1bl3L3ct3r/CVE-2026-4112.svg)

## CVE-2026-4106
 The HT Mega Addons for Elementor  WordPress plugin before 3.0.7 contains an unauthenticated AJAX action returning some PII (such as full name, city, state and country) of customers who placed orders in the last 7 days



- [https://github.com/ef3tr/CVE-2026-4106](https://github.com/ef3tr/CVE-2026-4106) :  ![starts](https://img.shields.io/github/stars/ef3tr/CVE-2026-4106.svg) ![forks](https://img.shields.io/github/forks/ef3tr/CVE-2026-4106.svg)

## CVE-2026-4092
 Path Traversal in Clasp impacting versions  3.2.0 allows a remote attacker to perform remote code execution via a malicious Google Apps Script project containing specially crafted filenames with directory traversal sequences.



- [https://github.com/g0w6y/CVE-2026-4092](https://github.com/g0w6y/CVE-2026-4092) :  ![starts](https://img.shields.io/github/stars/g0w6y/CVE-2026-4092.svg) ![forks](https://img.shields.io/github/forks/g0w6y/CVE-2026-4092.svg)

## CVE-2026-4077
 The Ecover Builder For Dummies plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'id' parameter of the 'ecover' shortcode in all versions up to and including 1.0. This is due to insufficient input sanitization and output escaping on the user-supplied 'id' shortcode attribute. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/lorenzofradeani/CVE-2026-40776](https://github.com/lorenzofradeani/CVE-2026-40776) :  ![starts](https://img.shields.io/github/stars/lorenzofradeani/CVE-2026-40776.svg) ![forks](https://img.shields.io/github/forks/lorenzofradeani/CVE-2026-40776.svg)

## CVE-2026-4057
 The Download Manager plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the `makeMediaPublic()` and `makeMediaPrivate()` functions in all versions up to, and including, 3.3.51. This is due to the functions only checking for `edit_posts` capability without verifying post ownership via `current_user_can('edit_post', $id)`, and the destructive operations executing before the admin-level check in `mediaAccessControl()`. This makes it possible for authenticated attackers, with Contributor-level access and above, to strip all protection metadata (password, access restrictions, private flag) from any media file they do not own, making admin-protected files publicly accessible via their direct URL.



- [https://github.com/zebbernCVE/CVE-2026-40579](https://github.com/zebbernCVE/CVE-2026-40579) :  ![starts](https://img.shields.io/github/stars/zebbernCVE/CVE-2026-40579.svg) ![forks](https://img.shields.io/github/forks/zebbernCVE/CVE-2026-40579.svg)

## CVE-2026-3910
 Inappropriate implementation in V8 in Google Chrome prior to 146.0.7680.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/5o1z/CVE-2026-3910](https://github.com/5o1z/CVE-2026-3910) :  ![starts](https://img.shields.io/github/stars/5o1z/CVE-2026-3910.svg) ![forks](https://img.shields.io/github/forks/5o1z/CVE-2026-3910.svg)

## CVE-2026-3909
 Out of bounds write in Skia in Google Chrome prior to 146.0.7680.75 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/anansi2safe/CVE-2026-3909-PoC](https://github.com/anansi2safe/CVE-2026-3909-PoC) :  ![starts](https://img.shields.io/github/stars/anansi2safe/CVE-2026-3909-PoC.svg) ![forks](https://img.shields.io/github/forks/anansi2safe/CVE-2026-3909-PoC.svg)

## CVE-2026-3891
 The Pix for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads due to missing capability check and missing file type validation in the 'lkn_pix_for_woocommerce_c6_save_settings' function in all versions up to, and including, 1.5.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2026-3891](https://github.com/Nxploited/CVE-2026-3891) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-3891.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-3891.svg)

- [https://github.com/AnggaTechI/Mass-Scanner-CVE-2026-3891](https://github.com/AnggaTechI/Mass-Scanner-CVE-2026-3891) :  ![starts](https://img.shields.io/github/stars/AnggaTechI/Mass-Scanner-CVE-2026-3891.svg) ![forks](https://img.shields.io/github/forks/AnggaTechI/Mass-Scanner-CVE-2026-3891.svg)

- [https://github.com/joshuavanderpoll/CVE-2026-3891](https://github.com/joshuavanderpoll/CVE-2026-3891) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2026-3891.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2026-3891.svg)

## CVE-2026-3888
 Local privilege escalation in snapd on Linux allows local attackers to get root privilege by re-creating snap's private /tmp directory when systemd-tmpfiles is configured to automatically clean up this directory. This issue affects Ubuntu 16.04 LTS, 18.04 LTS, 20.04 LTS, 22.04 LTS, and 24.04 LTS.



- [https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE](https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE) :  ![starts](https://img.shields.io/github/stars/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE.svg) ![forks](https://img.shields.io/github/forks/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE.svg)

- [https://github.com/nomaisthere/CVE-2026-3888](https://github.com/nomaisthere/CVE-2026-3888) :  ![starts](https://img.shields.io/github/stars/nomaisthere/CVE-2026-3888.svg) ![forks](https://img.shields.io/github/forks/nomaisthere/CVE-2026-3888.svg)

- [https://github.com/netw0rk7/CVE-2026-3888-PoC](https://github.com/netw0rk7/CVE-2026-3888-PoC) :  ![starts](https://img.shields.io/github/stars/netw0rk7/CVE-2026-3888-PoC.svg) ![forks](https://img.shields.io/github/forks/netw0rk7/CVE-2026-3888-PoC.svg)

- [https://github.com/fevar54/CVE-2026-3888-POC-all-from-the-Qualys-platform.](https://github.com/fevar54/CVE-2026-3888-POC-all-from-the-Qualys-platform.) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-3888-POC-all-from-the-Qualys-platform..svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-3888-POC-all-from-the-Qualys-platform..svg)

- [https://github.com/DanielTangnes/CVE-2026-3888](https://github.com/DanielTangnes/CVE-2026-3888) :  ![starts](https://img.shields.io/github/stars/DanielTangnes/CVE-2026-3888.svg) ![forks](https://img.shields.io/github/forks/DanielTangnes/CVE-2026-3888.svg)

- [https://github.com/Many-Hat-Group/Ubuntu-CVE-2026-3888-patcher](https://github.com/Many-Hat-Group/Ubuntu-CVE-2026-3888-patcher) :  ![starts](https://img.shields.io/github/stars/Many-Hat-Group/Ubuntu-CVE-2026-3888-patcher.svg) ![forks](https://img.shields.io/github/forks/Many-Hat-Group/Ubuntu-CVE-2026-3888-patcher.svg)

- [https://github.com/karimelsheikh1/HTB-Snapped-Writeup](https://github.com/karimelsheikh1/HTB-Snapped-Writeup) :  ![starts](https://img.shields.io/github/stars/karimelsheikh1/HTB-Snapped-Writeup.svg) ![forks](https://img.shields.io/github/forks/karimelsheikh1/HTB-Snapped-Writeup.svg)

## CVE-2026-3854
 An improper neutralization of special elements vulnerability was identified in GitHub Enterprise Server that allowed an attacker with push access to a repository to achieve remote code execution on the instance. During a git push operation, user-supplied push option values were not properly sanitized before being included in internal service headers. Because the internal header format used a delimiter character that could also appear in user input, an attacker could inject additional metadata fields through crafted push option values. This vulnerability was reported via the GitHub Bug Bounty program and has been fixed in GitHub Enterprise Server versions 3.14.25, 3.15.20, 3.16.16, 3.17.13, 3.18.7 and 3.19.4.



- [https://github.com/lysophavin18/CVE-2026-3854-PoC](https://github.com/lysophavin18/CVE-2026-3854-PoC) :  ![starts](https://img.shields.io/github/stars/lysophavin18/CVE-2026-3854-PoC.svg) ![forks](https://img.shields.io/github/forks/lysophavin18/CVE-2026-3854-PoC.svg)

- [https://github.com/LACHHAB-Anas/Exploit_CVE-2026-3854](https://github.com/LACHHAB-Anas/Exploit_CVE-2026-3854) :  ![starts](https://img.shields.io/github/stars/LACHHAB-Anas/Exploit_CVE-2026-3854.svg) ![forks](https://img.shields.io/github/forks/LACHHAB-Anas/Exploit_CVE-2026-3854.svg)

- [https://github.com/simondankelmann/cve-2026-3854-test](https://github.com/simondankelmann/cve-2026-3854-test) :  ![starts](https://img.shields.io/github/stars/simondankelmann/cve-2026-3854-test.svg) ![forks](https://img.shields.io/github/forks/simondankelmann/cve-2026-3854-test.svg)

- [https://github.com/5kr1pt/CVE-2026-3854](https://github.com/5kr1pt/CVE-2026-3854) :  ![starts](https://img.shields.io/github/stars/5kr1pt/CVE-2026-3854.svg) ![forks](https://img.shields.io/github/forks/5kr1pt/CVE-2026-3854.svg)

- [https://github.com/isagoakira/ghes-cve-scanner](https://github.com/isagoakira/ghes-cve-scanner) :  ![starts](https://img.shields.io/github/stars/isagoakira/ghes-cve-scanner.svg) ![forks](https://img.shields.io/github/forks/isagoakira/ghes-cve-scanner.svg)

## CVE-2026-3844
 The Breeze Cache plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'fetch_gravatar_from_remote' function in all versions up to, and including, 2.4.4. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. The vulnerability can only be exploited if "Host Files Locally - Gravatars" is enabled, which is disabled by default.



- [https://github.com/halilkirazkaya/CVE-2026-3844](https://github.com/halilkirazkaya/CVE-2026-3844) :  ![starts](https://img.shields.io/github/stars/halilkirazkaya/CVE-2026-3844.svg) ![forks](https://img.shields.io/github/forks/halilkirazkaya/CVE-2026-3844.svg)

- [https://github.com/dinosn/CVE-2026-3844](https://github.com/dinosn/CVE-2026-3844) :  ![starts](https://img.shields.io/github/stars/dinosn/CVE-2026-3844.svg) ![forks](https://img.shields.io/github/forks/dinosn/CVE-2026-3844.svg)

- [https://github.com/tausifzaman/CVE-2026-3844](https://github.com/tausifzaman/CVE-2026-3844) :  ![starts](https://img.shields.io/github/stars/tausifzaman/CVE-2026-3844.svg) ![forks](https://img.shields.io/github/forks/tausifzaman/CVE-2026-3844.svg)

- [https://github.com/sahmsec/CVE-2026-3844](https://github.com/sahmsec/CVE-2026-3844) :  ![starts](https://img.shields.io/github/stars/sahmsec/CVE-2026-3844.svg) ![forks](https://img.shields.io/github/forks/sahmsec/CVE-2026-3844.svg)

- [https://github.com/im-hanzou/CVE-2026-3844](https://github.com/im-hanzou/CVE-2026-3844) :  ![starts](https://img.shields.io/github/stars/im-hanzou/CVE-2026-3844.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/CVE-2026-3844.svg)

- [https://github.com/zycoder0day/CVE-2026-3844](https://github.com/zycoder0day/CVE-2026-3844) :  ![starts](https://img.shields.io/github/stars/zycoder0day/CVE-2026-3844.svg) ![forks](https://img.shields.io/github/forks/zycoder0day/CVE-2026-3844.svg)

- [https://github.com/0xgh057r3c0n/CVE-2026-3844](https://github.com/0xgh057r3c0n/CVE-2026-3844) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2026-3844.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2026-3844.svg)

- [https://github.com/rootdirective-sec/CVE-2026-3844-Lab](https://github.com/rootdirective-sec/CVE-2026-3844-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-3844-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-3844-Lab.svg)

## CVE-2026-3805
 When doing a second SMB request to the same host again, curl would wrongly use
a data pointer pointing into already freed memory.



- [https://github.com/Rat5ak/CVE-2026-3805-curl-SMB-UAF](https://github.com/Rat5ak/CVE-2026-3805-curl-SMB-UAF) :  ![starts](https://img.shields.io/github/stars/Rat5ak/CVE-2026-3805-curl-SMB-UAF.svg) ![forks](https://img.shields.io/github/forks/Rat5ak/CVE-2026-3805-curl-SMB-UAF.svg)

## CVE-2026-3796
 A weakness has been identified in Qi-ANXIN QAX Virus Removal up to 2025-10-22. The affected element is the function ZwTerminateProcess in the library QKSecureIO_Imp.sys of the component Mini Filter Driver. Executing a manipulation can lead to improper access controls. The attack is restricted to local execution. The exploit has been made available to the public and could be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/cwjchoi01/CVE-2026-3796](https://github.com/cwjchoi01/CVE-2026-3796) :  ![starts](https://img.shields.io/github/stars/cwjchoi01/CVE-2026-3796.svg) ![forks](https://img.shields.io/github/forks/cwjchoi01/CVE-2026-3796.svg)

## CVE-2026-3786
 A security flaw has been discovered in EasyCMS up to 1.6. The impacted element is an unknown function of the file /RbacuserAction.class.php of the component Request Parameter Handler. The manipulation of the argument _order results in sql injection. The attack can be launched remotely. The exploit has been released to the public and may be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/Mefhika120/CVE-2026-3786](https://github.com/Mefhika120/CVE-2026-3786) :  ![starts](https://img.shields.io/github/stars/Mefhika120/CVE-2026-3786.svg) ![forks](https://img.shields.io/github/forks/Mefhika120/CVE-2026-3786.svg)

## CVE-2026-3763
 A vulnerability was found in code-projects Simple Flight Ticket Booking System 1.0. The affected element is an unknown function of the file showhistory.php. The manipulation results in cross site scripting. It is possible to launch the attack remotely. The exploit has been made public and could be used.



- [https://github.com/SLO-CYBER-SEC/CVE-2026-37637](https://github.com/SLO-CYBER-SEC/CVE-2026-37637) :  ![starts](https://img.shields.io/github/stars/SLO-CYBER-SEC/CVE-2026-37637.svg) ![forks](https://img.shields.io/github/forks/SLO-CYBER-SEC/CVE-2026-37637.svg)

## CVE-2026-3727
 A vulnerability was found in Tenda F453 1.0.0.3. This vulnerability affects the function sub_3C6C0 of the file /goform/QuickIndex. The manipulation of the argument mit_linktype/PPPOEPassword results in stack-based buffer overflow. The attack may be launched remotely. The exploit has been made public and could be used.



- [https://github.com/vytlanikhil/CVE-2026-37272](https://github.com/vytlanikhil/CVE-2026-37272) :  ![starts](https://img.shields.io/github/stars/vytlanikhil/CVE-2026-37272.svg) ![forks](https://img.shields.io/github/forks/vytlanikhil/CVE-2026-37272.svg)

## CVE-2026-3698
 A vulnerability was identified in UTT HiPER 810G up to 1.7.7-171114. This affects the function strcpy of the file /goform/NTP. The manipulation leads to buffer overflow. The attack may be initiated remotely. The exploit is publicly available and might be used.



- [https://github.com/canomer/CVE-2026-36981-Kernel-EoP-PoC](https://github.com/canomer/CVE-2026-36981-Kernel-EoP-PoC) :  ![starts](https://img.shields.io/github/stars/canomer/CVE-2026-36981-Kernel-EoP-PoC.svg) ![forks](https://img.shields.io/github/forks/canomer/CVE-2026-36981-Kernel-EoP-PoC.svg)

- [https://github.com/canomer/CVE-2026-36980-Kernel-BSOD-DoS-PoC](https://github.com/canomer/CVE-2026-36980-Kernel-BSOD-DoS-PoC) :  ![starts](https://img.shields.io/github/stars/canomer/CVE-2026-36980-Kernel-BSOD-DoS-PoC.svg) ![forks](https://img.shields.io/github/forks/canomer/CVE-2026-36980-Kernel-BSOD-DoS-PoC.svg)

## CVE-2026-3584
 The Kali Forms plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 2.4.9 via the 'form_process' function. This is due to the 'prepare_post_data' function mapping user-supplied keys directly into internal placeholder storage, combined with the use of 'call_user_func' on these placeholder values. This makes it possible for unauthenticated attackers to execute code on the server.



- [https://github.com/Yucaerin/CVE-2026-3584](https://github.com/Yucaerin/CVE-2026-3584) :  ![starts](https://img.shields.io/github/stars/Yucaerin/CVE-2026-3584.svg) ![forks](https://img.shields.io/github/forks/Yucaerin/CVE-2026-3584.svg)

## CVE-2026-3516
 The Contact List plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the '_cl_map_iframe' parameter in all versions up to, and including, 3.0.18. This is due to insufficient input sanitization and output escaping when handling the Google Maps iframe custom field. The saveCustomFields() function in class-contact-list-custom-fields.php uses a regex to extract iframe tags from user input but does not validate or sanitize the iframe's attributes, allowing event handlers like 'onload' to be included. The extracted iframe HTML is stored via update_post_meta() and later rendered on the front-end in class-cl-public-card.php without any escaping or wp_kses filtering. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/d3kc4rt1/CVE-2026-3516](https://github.com/d3kc4rt1/CVE-2026-3516) :  ![starts](https://img.shields.io/github/stars/d3kc4rt1/CVE-2026-3516.svg) ![forks](https://img.shields.io/github/forks/d3kc4rt1/CVE-2026-3516.svg)

## CVE-2026-3502
 TrueConf Client downloads application update code and applies it without performing verification. An attacker who is able to influence the update delivery path can substitute a tampered update payload. If the payload is executed or installed by the updater, this may result in arbitrary code execution in the context of the updating process or user.



- [https://github.com/fevar54/CVE-2026-3502-Scanner---TrueConf-Vulnerability-Detection-Tool](https://github.com/fevar54/CVE-2026-3502-Scanner---TrueConf-Vulnerability-Detection-Tool) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-3502-Scanner---TrueConf-Vulnerability-Detection-Tool.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-3502-Scanner---TrueConf-Vulnerability-Detection-Tool.svg)

- [https://github.com/fevar54/CVE-2026-3502---TrueConf-Client-Update-Hijacking-PoC](https://github.com/fevar54/CVE-2026-3502---TrueConf-Client-Update-Hijacking-PoC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-3502---TrueConf-Client-Update-Hijacking-PoC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-3502---TrueConf-Client-Update-Hijacking-PoC.svg)

## CVE-2026-3494
 In MariaDB server version through 11.8.5, when server audit plugin is enabled with server_audit_events variable configured with QUERY_DCL, QUERY_DDL, or QUERY_DML filtering, if an authenticated database user invokes a SQL statement prefixed with double-hyphen (—) or hash (#) style comments, the statement is not logged.



- [https://github.com/KKongTen/CVE-2026-3494_Verfication](https://github.com/KKongTen/CVE-2026-3494_Verfication) :  ![starts](https://img.shields.io/github/stars/KKongTen/CVE-2026-3494_Verfication.svg) ![forks](https://img.shields.io/github/forks/KKongTen/CVE-2026-3494_Verfication.svg)

## CVE-2026-3395
 A flaw has been found in MaxSite CMS up to 109.1. This impacts the function eval of the file application/maxsite/admin/plugins/editor_markitup/preview-ajax.php of the component MarkItUp Preview AJAX Endpoint. Executing a manipulation can lead to code injection. It is possible to launch the attack remotely. The exploit has been published and may be used. Upgrading to version 109.2 will fix this issue. This patch is called 08937a3c5d672a242d68f53e9fccf8a748820ef3. You should upgrade the affected component. The code maintainer was informed beforehand about the issues. He reacted very fast and highly professional.



- [https://github.com/mbanyamer/CVE-2026-3395-MaxSite-CMS-Unauthenticated-RCE](https://github.com/mbanyamer/CVE-2026-3395-MaxSite-CMS-Unauthenticated-RCE) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2026-3395-MaxSite-CMS-Unauthenticated-RCE.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2026-3395-MaxSite-CMS-Unauthenticated-RCE.svg)

- [https://github.com/rootdirective-sec/CVE-2026-3395-Lab](https://github.com/rootdirective-sec/CVE-2026-3395-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-3395-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-3395-Lab.svg)

## CVE-2026-3304
 Multer is a node.js middleware for handling `multipart/form-data`. A vulnerability in Multer prior to version 2.1.0 allows an attacker to trigger a Denial of Service (DoS) by sending malformed requests, potentially causing resource exhaustion. Users should upgrade to version 2.1.0 to receive a patch. No known workarounds are available.



- [https://github.com/Mkway/CVE-2026-3304](https://github.com/Mkway/CVE-2026-3304) :  ![starts](https://img.shields.io/github/stars/Mkway/CVE-2026-3304.svg) ![forks](https://img.shields.io/github/forks/Mkway/CVE-2026-3304.svg)

## CVE-2026-3288
 A security issue was discovered in ingress-nginx where the `nginx.ingress.kubernetes.io/rewrite-target` Ingress annotation can be used to inject configuration into nginx. This can lead to arbitrary code execution in the context of the ingress-nginx controller, and disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)



- [https://github.com/SnailSploit/CVE-2026-3288](https://github.com/SnailSploit/CVE-2026-3288) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2026-3288.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2026-3288.svg)

- [https://github.com/bvabhishek/CVE-2026-3288-lab](https://github.com/bvabhishek/CVE-2026-3288-lab) :  ![starts](https://img.shields.io/github/stars/bvabhishek/CVE-2026-3288-lab.svg) ![forks](https://img.shields.io/github/forks/bvabhishek/CVE-2026-3288-lab.svg)

## CVE-2026-3228
 The NextScripts: Social Networks Auto-Poster plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the `[nxs_fbembed]` shortcode in all versions up to, and including, 4.4.6. This is due to insufficient input sanitization and output escaping on the `snapFB` post meta value. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/NULL200OK/CVE-2026-3228](https://github.com/NULL200OK/CVE-2026-3228) :  ![starts](https://img.shields.io/github/stars/NULL200OK/CVE-2026-3228.svg) ![forks](https://img.shields.io/github/forks/NULL200OK/CVE-2026-3228.svg)

## CVE-2026-3171
 A flaw has been found in SourceCodester/Patrick Mvuma Patients Waiting Area Queue Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /queue.php. This manipulation of the argument firstname/lastname causes cross site scripting. The attack is possible to be carried out remotely. The exploit has been published and may be used.



- [https://github.com/archana1122m/CVE-disclosures](https://github.com/archana1122m/CVE-disclosures) :  ![starts](https://img.shields.io/github/stars/archana1122m/CVE-disclosures.svg) ![forks](https://img.shields.io/github/forks/archana1122m/CVE-disclosures.svg)

## CVE-2026-3170
 A vulnerability was detected in SourceCodester/Patrick Mvuma Patients Waiting Area Queue Management System 1.0. Affected is an unknown function of the file /patient-search.php. The manipulation of the argument First Name/Last Name results in cross site scripting. The attack can be executed remotely. The exploit is now public and may be used.



- [https://github.com/archana1122m/CVE-disclosures](https://github.com/archana1122m/CVE-disclosures) :  ![starts](https://img.shields.io/github/stars/archana1122m/CVE-disclosures.svg) ![forks](https://img.shields.io/github/forks/archana1122m/CVE-disclosures.svg)

## CVE-2026-3134
 A security flaw has been discovered in itsourcecode News Portal Project 1.0. The affected element is an unknown function of the file /newsportal/admin/edit-category.php. The manipulation of the argument Category results in sql injection. The attack may be performed from remote. The exploit has been released to the public and may be used for attacks.



- [https://github.com/Sc2-Ciberdefensa/cve-2026-31341-copy-fail-checker](https://github.com/Sc2-Ciberdefensa/cve-2026-31341-copy-fail-checker) :  ![starts](https://img.shields.io/github/stars/Sc2-Ciberdefensa/cve-2026-31341-copy-fail-checker.svg) ![forks](https://img.shields.io/github/forks/Sc2-Ciberdefensa/cve-2026-31341-copy-fail-checker.svg)

## CVE-2026-3126
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.



- [https://github.com/0xrixet/Craftcms-PoC-CVE-2026-31266](https://github.com/0xrixet/Craftcms-PoC-CVE-2026-31266) :  ![starts](https://img.shields.io/github/stars/0xrixet/Craftcms-PoC-CVE-2026-31266.svg) ![forks](https://img.shields.io/github/forks/0xrixet/Craftcms-PoC-CVE-2026-31266.svg)

## CVE-2026-3098
 The Smart Slider 3 plugin for WordPress is vulnerable to Arbitrary File Read in all versions up to, and including, 3.5.1.33 via the 'actionExportAll' function. This makes it possible for authenticated attackers, with Subscriber-level access and above, to read the contents of arbitrary files on the server, which can contain sensitive information.



- [https://github.com/George0Papasotiriou/LLM-Jailbreak-via-Chain-of-Logic-Injection-CVE-2026-3098](https://github.com/George0Papasotiriou/LLM-Jailbreak-via-Chain-of-Logic-Injection-CVE-2026-3098) :  ![starts](https://img.shields.io/github/stars/George0Papasotiriou/LLM-Jailbreak-via-Chain-of-Logic-Injection-CVE-2026-3098.svg) ![forks](https://img.shields.io/github/forks/George0Papasotiriou/LLM-Jailbreak-via-Chain-of-Logic-Injection-CVE-2026-3098.svg)

## CVE-2026-3055
 Insufficient input validation in NetScaler ADC and NetScaler Gateway when configured as a SAML IDP leading to memory overread



- [https://github.com/0xBlackash/CVE-2026-3055](https://github.com/0xBlackash/CVE-2026-3055) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-3055.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-3055.svg)

- [https://github.com/NetVanguard-cmd/CVE-2026-3055](https://github.com/NetVanguard-cmd/CVE-2026-3055) :  ![starts](https://img.shields.io/github/stars/NetVanguard-cmd/CVE-2026-3055.svg) ![forks](https://img.shields.io/github/forks/NetVanguard-cmd/CVE-2026-3055.svg)

- [https://github.com/l0lsec/check-cve-2026-3055-netscaler](https://github.com/l0lsec/check-cve-2026-3055-netscaler) :  ![starts](https://img.shields.io/github/stars/l0lsec/check-cve-2026-3055-netscaler.svg) ![forks](https://img.shields.io/github/forks/l0lsec/check-cve-2026-3055-netscaler.svg)

- [https://github.com/fevar54/CVE-2026-3055-Scanner---Herramienta-de-Detecci-n](https://github.com/fevar54/CVE-2026-3055-Scanner---Herramienta-de-Detecci-n) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-3055-Scanner---Herramienta-de-Detecci-n.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-3055-Scanner---Herramienta-de-Detecci-n.svg)

- [https://github.com/fevar54/CVE-2026-3055---Citrix-NetScaler-Memory-Overread-PoC](https://github.com/fevar54/CVE-2026-3055---Citrix-NetScaler-Memory-Overread-PoC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-3055---Citrix-NetScaler-Memory-Overread-PoC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-3055---Citrix-NetScaler-Memory-Overread-PoC.svg)

## CVE-2026-3049
 A vulnerability was detected in horilla-opensource horilla up to 1.0.2. This issue affects the function get of the file horilla_generics/global_search.py of the component Query Parameter Handler. The manipulation of the argument prev_url results in open redirect. The attack can be executed remotely. The exploit is now public and may be used. Upgrading to version 1.0.3 is capable of addressing this issue. The patch is identified as 730b5a44ff060916780c44a4bdbc8ced70a2cd27. The affected component should be upgraded.



- [https://github.com/Mehdi-Ben-Hamou/CVE-2026-30498](https://github.com/Mehdi-Ben-Hamou/CVE-2026-30498) :  ![starts](https://img.shields.io/github/stars/Mehdi-Ben-Hamou/CVE-2026-30498.svg) ![forks](https://img.shields.io/github/forks/Mehdi-Ben-Hamou/CVE-2026-30498.svg)

## CVE-2026-3008
 Successful exploitation of the
string injection vulnerability could allow an attacker to obtain memory address
information or crash the application.



- [https://github.com/llgsjsm/cve-2026-3008](https://github.com/llgsjsm/cve-2026-3008) :  ![starts](https://img.shields.io/github/stars/llgsjsm/cve-2026-3008.svg) ![forks](https://img.shields.io/github/forks/llgsjsm/cve-2026-3008.svg)

- [https://github.com/rakeshelamaran98/CVE-2026-30081](https://github.com/rakeshelamaran98/CVE-2026-30081) :  ![starts](https://img.shields.io/github/stars/rakeshelamaran98/CVE-2026-30081.svg) ![forks](https://img.shields.io/github/forks/rakeshelamaran98/CVE-2026-30081.svg)

## CVE-2026-3003
 The Vagaro Booking Widget plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘vagaro_code’ parameter in all versions up to, and including, 0.3 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/bx33661/CVE-2026-30039](https://github.com/bx33661/CVE-2026-30039) :  ![starts](https://img.shields.io/github/stars/bx33661/CVE-2026-30039.svg) ![forks](https://img.shields.io/github/forks/bx33661/CVE-2026-30039.svg)

## CVE-2026-2991
 The KiviCare – Clinic & Patient Management System (EHR) plugin for WordPress is vulnerable to Authentication Bypass in all versions up to, and including, 4.1.2. This is due to the `patientSocialLogin()` function not verifying the social provider access token before authenticating a user. This makes it possible for unauthenticated attackers to log in as any patient registered on the system by providing only their email address and an arbitrary value for the access token, bypassing all credential verification. The attacker gains access to sensitive medical records, appointments, prescriptions, and billing information (PII/PHI breach). Additionally, authentication cookies are set before the role check, meaning the auth cookies for non-patient users (including administrators) are also set in the HTTP response headers, even though a 403 response is returned.



- [https://github.com/joshuavanderpoll/CVE-2026-2991](https://github.com/joshuavanderpoll/CVE-2026-2991) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2026-2991.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2026-2991.svg)

- [https://github.com/Jumpthereness578/CVE-2026-2991](https://github.com/Jumpthereness578/CVE-2026-2991) :  ![starts](https://img.shields.io/github/stars/Jumpthereness578/CVE-2026-2991.svg) ![forks](https://img.shields.io/github/forks/Jumpthereness578/CVE-2026-2991.svg)

## CVE-2026-2964
 A vulnerability was identified in higuma web-audio-recorder-js 0.1/0.1.1. Impacted is the function extend in the library lib/WebAudioRecorder.js of the component Dynamic Config Handling. Such manipulation leads to improperly controlled modification of object prototype attributes. It is possible to launch the attack remotely. Attacks of this nature are highly complex. The exploitability is considered difficult. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/thegenetic/CVE-2026-2964-Lab](https://github.com/thegenetic/CVE-2026-2964-Lab) :  ![starts](https://img.shields.io/github/stars/thegenetic/CVE-2026-2964-Lab.svg) ![forks](https://img.shields.io/github/forks/thegenetic/CVE-2026-2964-Lab.svg)

## CVE-2026-2898
 A vulnerability was detected in funadmin up to 7.1.0-rc4. This issue affects the function getMember of the file app/common/service/AuthCloudService.php of the component Backend Endpoint. The manipulation of the argument cloud_account results in deserialization. The attack may be performed from remote. The exploit is now public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/aykhan32/CVE-2026-2898-FunAdmin-Deserialization](https://github.com/aykhan32/CVE-2026-2898-FunAdmin-Deserialization) :  ![starts](https://img.shields.io/github/stars/aykhan32/CVE-2026-2898-FunAdmin-Deserialization.svg) ![forks](https://img.shields.io/github/forks/aykhan32/CVE-2026-2898-FunAdmin-Deserialization.svg)

## CVE-2026-2796
 JIT miscompilation in the JavaScript: WebAssembly component. This vulnerability was fixed in Firefox 148 and Thunderbird 148.



- [https://github.com/WostGit/CVE-2026-2796](https://github.com/WostGit/CVE-2026-2796) :  ![starts](https://img.shields.io/github/stars/WostGit/CVE-2026-2796.svg) ![forks](https://img.shields.io/github/forks/WostGit/CVE-2026-2796.svg)

- [https://github.com/WostGit/cve-2026-2796-repro](https://github.com/WostGit/cve-2026-2796-repro) :  ![starts](https://img.shields.io/github/stars/WostGit/cve-2026-2796-repro.svg) ![forks](https://img.shields.io/github/forks/WostGit/cve-2026-2796-repro.svg)

## CVE-2026-2763
 Use-after-free in the JavaScript Engine component. This vulnerability was fixed in Firefox 148, Firefox ESR 115.33, Firefox ESR 140.8, Thunderbird 148, and Thunderbird 140.8.



- [https://github.com/ppwwiinn/CVE-2026-2763-POC](https://github.com/ppwwiinn/CVE-2026-2763-POC) :  ![starts](https://img.shields.io/github/stars/ppwwiinn/CVE-2026-2763-POC.svg) ![forks](https://img.shields.io/github/forks/ppwwiinn/CVE-2026-2763-POC.svg)

## CVE-2026-2751
 Blind SQL Injection via unsanitized array keys in Service Dependencies deletion. Vulnerability in Centreon Centreon Web on Central Server on Linux (Service Dependencies modules) allows Blind SQL Injection.This issue affects Centreon Web on Central Server before 25.10.8, 24.10.20, 24.04.24.



- [https://github.com/hakaioffsec/Centreon-Exploits-2026](https://github.com/hakaioffsec/Centreon-Exploits-2026) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/Centreon-Exploits-2026.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/Centreon-Exploits-2026.svg)

## CVE-2026-2750
 Improper Input Validation vulnerability in Centreon Centreon Open Tickets on Central Server on Linux (Centreon Open Tickets modules).This issue affects Centreon Open Tickets on Central Server: from all before 25.10; 24.10;24.04.



- [https://github.com/hakaioffsec/Centreon-Exploits-2026](https://github.com/hakaioffsec/Centreon-Exploits-2026) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/Centreon-Exploits-2026.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/Centreon-Exploits-2026.svg)

## CVE-2026-2749
 Vulnerability in Centreon Centreon Open Tickets on Central Server on Linux (Centroen Open Ticket modules).This issue affects Centreon Open Tickets on Central Server: from all before 25.10.3, 24.10.8, 24.04.7.



- [https://github.com/hakaioffsec/Centreon-Exploits-2026](https://github.com/hakaioffsec/Centreon-Exploits-2026) :  ![starts](https://img.shields.io/github/stars/hakaioffsec/Centreon-Exploits-2026.svg) ![forks](https://img.shields.io/github/forks/hakaioffsec/Centreon-Exploits-2026.svg)

## CVE-2026-2699
 Customer Managed ShareFile Storage Zones Controller (SZC) allows an unauthenticated attacker to access restricted configuration pages. This leads to changing system configuration and potential remote code execution.



- [https://github.com/watchtowrlabs/watchTowr-vs-Progress-ShareFile-CVE-2026-2699](https://github.com/watchtowrlabs/watchTowr-vs-Progress-ShareFile-CVE-2026-2699) :  ![starts](https://img.shields.io/github/stars/watchtowrlabs/watchTowr-vs-Progress-ShareFile-CVE-2026-2699.svg) ![forks](https://img.shields.io/github/forks/watchtowrlabs/watchTowr-vs-Progress-ShareFile-CVE-2026-2699.svg)

- [https://github.com/0xBlackash/CVE-2026-2699](https://github.com/0xBlackash/CVE-2026-2699) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-2699.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-2699.svg)

## CVE-2026-2690
 A flaw has been found in itsourcecode Event Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /admin/ajax.php?action=login of the component Admin Login. This manipulation of the argument Username causes sql injection. It is possible to initiate the attack remotely. The exploit has been published and may be used.



- [https://github.com/John-Jung/CVE-2026-26903-PoC](https://github.com/John-Jung/CVE-2026-26903-PoC) :  ![starts](https://img.shields.io/github/stars/John-Jung/CVE-2026-26903-PoC.svg) ![forks](https://img.shields.io/github/forks/John-Jung/CVE-2026-26903-PoC.svg)

## CVE-2026-2670
 A vulnerability was identified in Advantech WISE-6610 1.2.1_20251110. Affected is an unknown function of the file /cgi-bin/luci/admin/openvpn_apply of the component Background Management. Such manipulation of the argument delete_file leads to os command injection. The attack can be executed remotely. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/ali-py3/exploit-CVE-2026-2670](https://github.com/ali-py3/exploit-CVE-2026-2670) :  ![starts](https://img.shields.io/github/stars/ali-py3/exploit-CVE-2026-2670.svg) ![forks](https://img.shields.io/github/forks/ali-py3/exploit-CVE-2026-2670.svg)

## CVE-2026-2636
 This vulnerability is caused by a CWE‑159: "Improper Handling of Invalid Use of Special Elements" weakness, which leads to an unrecoverable inconsistency in the CLFS.sys driver. This condition forces a call to the KeBugCheckEx function, allowing an unprivileged user to trigger a system crash. Microsoft silently fixed this vulnerability in the September 2025 cumulative update for Windows 11 2024 LTSC and Windows Server 2025. Windows 25H2 (released in September) was released with the patch. Windows 1123h2 and earlier versions remain vulnerable.



- [https://github.com/oxfemale/CVE-2026-2636_PoC](https://github.com/oxfemale/CVE-2026-2636_PoC) :  ![starts](https://img.shields.io/github/stars/oxfemale/CVE-2026-2636_PoC.svg) ![forks](https://img.shields.io/github/forks/oxfemale/CVE-2026-2636_PoC.svg)

- [https://github.com/uname1able/CVE-2026-2636](https://github.com/uname1able/CVE-2026-2636) :  ![starts](https://img.shields.io/github/stars/uname1able/CVE-2026-2636.svg) ![forks](https://img.shields.io/github/forks/uname1able/CVE-2026-2636.svg)

## CVE-2026-2631
 The Datalogics Ecommerce Delivery  WordPress plugin before 2.6.60 exposes an unauthenticated REST endpoint that allows any remote user to modify the option `datalogics_token` without verification. This token is subsequently used for authentication in a protected endpoint that allows users to perform arbitrary WordPress `update_option()` operations. Attackers can use this to enable registartion and to set the default role as Administrator.



- [https://github.com/AnggaTechI/Mass-Scanner-CVE-2026-2631](https://github.com/AnggaTechI/Mass-Scanner-CVE-2026-2631) :  ![starts](https://img.shields.io/github/stars/AnggaTechI/Mass-Scanner-CVE-2026-2631.svg) ![forks](https://img.shields.io/github/forks/AnggaTechI/Mass-Scanner-CVE-2026-2631.svg)

- [https://github.com/Nxploited/CVE-2026-2631](https://github.com/Nxploited/CVE-2026-2631) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-2631.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-2631.svg)

## CVE-2026-2600
 The ElementsKit Elementor Addons and Templates plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'ekit_tab_title' parameter in the Simple Tab widget in all versions up to, and including, 3.7.9 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/FOLKS-iwd/CVE-2026-2600-POC](https://github.com/FOLKS-iwd/CVE-2026-2600-POC) :  ![starts](https://img.shields.io/github/stars/FOLKS-iwd/CVE-2026-2600-POC.svg) ![forks](https://img.shields.io/github/forks/FOLKS-iwd/CVE-2026-2600-POC.svg)

## CVE-2026-2576
 The Business Directory Plugin – Easy Listing Directories for WordPress plugin for WordPress is vulnerable to time-based SQL Injection via the 'payment' parameter in all versions up to, and including, 6.4.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.



- [https://github.com/SowatKheang/CVE_2026_2576_PoC](https://github.com/SowatKheang/CVE_2026_2576_PoC) :  ![starts](https://img.shields.io/github/stars/SowatKheang/CVE_2026_2576_PoC.svg) ![forks](https://img.shields.io/github/forks/SowatKheang/CVE_2026_2576_PoC.svg)

## CVE-2026-2472
 Stored Cross-Site Scripting (XSS) in the _genai/_evals_visualization component of Google Cloud Vertex AI SDK (google-cloud-aiplatform) versions from 1.98.0 up to (but not including) 1.131.0 allows an unauthenticated remote attacker to execute arbitrary JavaScript in a victim's Jupyter or Colab environment via injecting script escape sequences into model evaluation results or dataset JSON data.



- [https://github.com/JoshuaProvoste/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud](https://github.com/JoshuaProvoste/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud) :  ![starts](https://img.shields.io/github/stars/JoshuaProvoste/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud.svg) ![forks](https://img.shields.io/github/forks/JoshuaProvoste/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud.svg)

- [https://github.com/megafart1/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud](https://github.com/megafart1/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud) :  ![starts](https://img.shields.io/github/stars/megafart1/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud.svg) ![forks](https://img.shields.io/github/forks/megafart1/CVE-2026-2472-Vertex-AI-SDK-Google-Cloud.svg)

## CVE-2026-2461
 Mattermost Plugins versions =11.3 11.0.3 11.2.2 10.10.11.0 fail to implement authorisation checks on comment block modifications, which allows an authorised attacker with editor permission to modify comments created by other board members.  Mattermost Advisory ID: MMSA-2025-00559



- [https://github.com/destiny-creates/CVE-2026-2461-poc](https://github.com/destiny-creates/CVE-2026-2461-poc) :  ![starts](https://img.shields.io/github/stars/destiny-creates/CVE-2026-2461-poc.svg) ![forks](https://img.shields.io/github/forks/destiny-creates/CVE-2026-2461-poc.svg)

## CVE-2026-2441
 Use after free in CSS in Google Chrome prior to 145.0.7632.75 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)



- [https://github.com/huseyinstif/CVE-2026-2441-PoC](https://github.com/huseyinstif/CVE-2026-2441-PoC) :  ![starts](https://img.shields.io/github/stars/huseyinstif/CVE-2026-2441-PoC.svg) ![forks](https://img.shields.io/github/forks/huseyinstif/CVE-2026-2441-PoC.svg)

- [https://github.com/fartlover37/CVE-2026-2441-PoC](https://github.com/fartlover37/CVE-2026-2441-PoC) :  ![starts](https://img.shields.io/github/stars/fartlover37/CVE-2026-2441-PoC.svg) ![forks](https://img.shields.io/github/forks/fartlover37/CVE-2026-2441-PoC.svg)

- [https://github.com/NetVanguard-cmd/CVE-2026-2441](https://github.com/NetVanguard-cmd/CVE-2026-2441) :  ![starts](https://img.shields.io/github/stars/NetVanguard-cmd/CVE-2026-2441.svg) ![forks](https://img.shields.io/github/forks/NetVanguard-cmd/CVE-2026-2441.svg)

- [https://github.com/MartinaStarone/CVE-2026-2441](https://github.com/MartinaStarone/CVE-2026-2441) :  ![starts](https://img.shields.io/github/stars/MartinaStarone/CVE-2026-2441.svg) ![forks](https://img.shields.io/github/forks/MartinaStarone/CVE-2026-2441.svg)

- [https://github.com/theemperorspath/CVE-2026-2441-PoC](https://github.com/theemperorspath/CVE-2026-2441-PoC) :  ![starts](https://img.shields.io/github/stars/theemperorspath/CVE-2026-2441-PoC.svg) ![forks](https://img.shields.io/github/forks/theemperorspath/CVE-2026-2441-PoC.svg)

- [https://github.com/D3b0j33t/CVE-2026-2441-PoC](https://github.com/D3b0j33t/CVE-2026-2441-PoC) :  ![starts](https://img.shields.io/github/stars/D3b0j33t/CVE-2026-2441-PoC.svg) ![forks](https://img.shields.io/github/forks/D3b0j33t/CVE-2026-2441-PoC.svg)

- [https://github.com/atiilla/CVE-2026-2441_PoC](https://github.com/atiilla/CVE-2026-2441_PoC) :  ![starts](https://img.shields.io/github/stars/atiilla/CVE-2026-2441_PoC.svg) ![forks](https://img.shields.io/github/forks/atiilla/CVE-2026-2441_PoC.svg)

## CVE-2026-2413
 The Ally – Web Accessibility & Usability plugin for WordPress is vulnerable to SQL Injection via the URL path in all versions up to, and including, 4.0.3. This is due to insufficient escaping on the user-supplied URL parameter in the `get_global_remediations()` method, where it is directly concatenated into an SQL JOIN clause without proper sanitization for SQL context. While `esc_url_raw()` is applied for URL safety, it does not prevent SQL metacharacters (single quotes, parentheses) from being injected. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database via time-based blind SQL injection techniques. The Remediation module must be active, which requires the plugin to be connected to an Elementor account.



- [https://github.com/p3Nt3st3r-sTAr/CVE-2026-2413-POC](https://github.com/p3Nt3st3r-sTAr/CVE-2026-2413-POC) :  ![starts](https://img.shields.io/github/stars/p3Nt3st3r-sTAr/CVE-2026-2413-POC.svg) ![forks](https://img.shields.io/github/forks/p3Nt3st3r-sTAr/CVE-2026-2413-POC.svg)

## CVE-2026-2256
 A command injection vulnerability in ModelScope's ms-agent versions v1.6.0rc1 and earlier exists, allowing an attacker to execute arbitrary operating system commands through crafted prompt-derived input.



- [https://github.com/Itamar-Yochpaz/CVE-2026-2256-PoC](https://github.com/Itamar-Yochpaz/CVE-2026-2256-PoC) :  ![starts](https://img.shields.io/github/stars/Itamar-Yochpaz/CVE-2026-2256-PoC.svg) ![forks](https://img.shields.io/github/forks/Itamar-Yochpaz/CVE-2026-2256-PoC.svg)

## CVE-2026-2184
 A vulnerability was detected in Great Developers Certificate Generation System up to 97171bb0e5e22e52eacf4e4fa81773e5f3cffb73. This vulnerability affects unknown code of the file /restructured/csv.php. The manipulation of the argument photo results in os command injection. The attack can be executed remotely. This product implements a rolling release for ongoing delivery, which means version information for affected or updated releases is unavailable. The code repository of the project has not been active for many years.



- [https://github.com/blaxkmiradev/CVE-2026-21847-Hardcoded-AES-Encryption-Key-in-DPDC-Customer-Portal](https://github.com/blaxkmiradev/CVE-2026-21847-Hardcoded-AES-Encryption-Key-in-DPDC-Customer-Portal) :  ![starts](https://img.shields.io/github/stars/blaxkmiradev/CVE-2026-21847-Hardcoded-AES-Encryption-Key-in-DPDC-Customer-Portal.svg) ![forks](https://img.shields.io/github/forks/blaxkmiradev/CVE-2026-21847-Hardcoded-AES-Encryption-Key-in-DPDC-Customer-Portal.svg)

## CVE-2026-2113
 A security vulnerability has been detected in yuan1994 tpadmin up to 1.3.12. This affects an unknown part in the library /public/static/admin/lib/webuploader/0.1.5/server/preview.php of the component WebUploader. The manipulation leads to deserialization. The attack is possible to be carried out remotely. The exploit has been disclosed publicly and may be used. This vulnerability only affects products that are no longer supported by the maintainer.



- [https://github.com/MaxMnMl/tpadmin-CVE-2026-2113-poc](https://github.com/MaxMnMl/tpadmin-CVE-2026-2113-poc) :  ![starts](https://img.shields.io/github/stars/MaxMnMl/tpadmin-CVE-2026-2113-poc.svg) ![forks](https://img.shields.io/github/forks/MaxMnMl/tpadmin-CVE-2026-2113-poc.svg)

## CVE-2026-2058
 A flaw has been found in mathurvishal CloudClassroom-PHP-Project up to 5dadec098bfbbf3300d60c3494db3fb95b66e7be. This impacts an unknown function of the file /postquerypublic.php of the component Post Query Details Page. This manipulation of the argument gnamex causes sql injection. The attack is possible to be carried out remotely. The exploit has been published and may be used. This product adopts a rolling release strategy to maintain continuous delivery. Therefore, version details for affected or updated releases cannot be specified. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/carlosalbertotuma/CVE-2026-2058-PoC](https://github.com/carlosalbertotuma/CVE-2026-2058-PoC) :  ![starts](https://img.shields.io/github/stars/carlosalbertotuma/CVE-2026-2058-PoC.svg) ![forks](https://img.shields.io/github/forks/carlosalbertotuma/CVE-2026-2058-PoC.svg)

## CVE-2026-2005
 Heap buffer overflow in PostgreSQL pgcrypto allows a ciphertext provider to execute arbitrary code as the operating system user running the database.  Versions before PostgreSQL 18.2, 17.8, 16.12, 15.16, and 14.21 are affected.



- [https://github.com/stvm8/CVE-2026-2005_lab](https://github.com/stvm8/CVE-2026-2005_lab) :  ![starts](https://img.shields.io/github/stars/stvm8/CVE-2026-2005_lab.svg) ![forks](https://img.shields.io/github/forks/stvm8/CVE-2026-2005_lab.svg)

## CVE-2026-1999
 An incorrect authorization vulnerability was identified in GitHub Enterprise Server that allowed an attacker to merge their own pull request into a repository without having push access by exploiting an authorization bypass in the enable_auto_merge mutation for pull requests. This issue only affected repositories that allow forking as the attack relies on opening a pull request from an attacker-controlled fork into the target repository. Exploitation was only possible in specific scenarios. It required a clean pull request status and only applied to branches without branch protection rules enabled. This vulnerability affected GitHub Enterprise Server versions prior to 3.19.2, 3.18.5, and 3.17.11, and was fixed in versions 3.19.2, 3.18.5, and 3.17.11. This vulnerability was reported via the GitHub Bug Bounty program.



- [https://github.com/jwde/automerge-test](https://github.com/jwde/automerge-test) :  ![starts](https://img.shields.io/github/stars/jwde/automerge-test.svg) ![forks](https://img.shields.io/github/forks/jwde/automerge-test.svg)

## CVE-2026-1953
 Nukegraphic CMS v3.1.2 contains a stored cross-site scripting (XSS) vulnerability in the user profile edit functionality at /ngc-cms/user-edit-profile.php. The application fails to properly sanitize user input in the name field before storing it in the database and rendering it across multiple CMS pages. An authenticated attacker with low privileges can inject malicious JavaScript payloads through the profile edit request, which are then executed site-wide whenever the affected user's name is displayed. This allows the attacker to execute arbitrary JavaScript in the context of other users' sessions, potentially leading to session hijacking, credential theft, or unauthorized actions performed on behalf of victims.



- [https://github.com/carlosbudiman/CVE-2026-1953-Disclosure](https://github.com/carlosbudiman/CVE-2026-1953-Disclosure) :  ![starts](https://img.shields.io/github/stars/carlosbudiman/CVE-2026-1953-Disclosure.svg) ![forks](https://img.shields.io/github/forks/carlosbudiman/CVE-2026-1953-Disclosure.svg)

## CVE-2026-1937
 The YayMail – WooCommerce Email Customizer plugin for WordPress is vulnerable to unauthorized modification of data that can lead to privilege escalation due to a missing capability check on the `yaymail_import_state` AJAX action in all versions up to, and including, 4.3.2. This makes it possible for authenticated attackers, with Shop Manager-level access and above, to update arbitrary options on the WordPress site. This can be leveraged to update the default role for registration to administrator and enable user registration for attackers to gain administrative user access to a vulnerable site.



- [https://github.com/Nxploited/CVE-2026-1937](https://github.com/Nxploited/CVE-2026-1937) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-1937.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-1937.svg)

## CVE-2026-1880
 An Incorrect Permission Assignment for Critical Resource vulnerability in the ASUS DriverHub update process allows privilege escalation due to improper protection of required execution resources during the validation phase, permitting a local user to make unprivileged modifications. This allows the altered resource to pass system checks and be executed with elevated privileges upon a user-initiated update.
Refer to the 'Security Update for ASUS DriverHub' section on the ASUS Security Advisory for more information.



- [https://github.com/seokjohn/CVE-2026-1880](https://github.com/seokjohn/CVE-2026-1880) :  ![starts](https://img.shields.io/github/stars/seokjohn/CVE-2026-1880.svg) ![forks](https://img.shields.io/github/forks/seokjohn/CVE-2026-1880.svg)

## CVE-2026-1844
 The PixelYourSite PRO plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'pysTrafficSource' parameter and the 'pys_landing_page' parameter in all versions up to, and including, 12.4.0.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.



- [https://github.com/adamshaikhma/CVE-2026-1844](https://github.com/adamshaikhma/CVE-2026-1844) :  ![starts](https://img.shields.io/github/stars/adamshaikhma/CVE-2026-1844.svg) ![forks](https://img.shields.io/github/forks/adamshaikhma/CVE-2026-1844.svg)

## CVE-2026-1731
 BeyondTrust Remote Support (RS) and certain older versions of Privileged Remote Access (PRA) contain a critical pre-authentication remote code execution vulnerability. By sending specially crafted requests, an unauthenticated remote attacker may be able to execute operating system commands in the context of the site user.



- [https://github.com/win3zz/CVE-2026-1731](https://github.com/win3zz/CVE-2026-1731) :  ![starts](https://img.shields.io/github/stars/win3zz/CVE-2026-1731.svg) ![forks](https://img.shields.io/github/forks/win3zz/CVE-2026-1731.svg)

- [https://github.com/jakubie07/CVE-2026-1731](https://github.com/jakubie07/CVE-2026-1731) :  ![starts](https://img.shields.io/github/stars/jakubie07/CVE-2026-1731.svg) ![forks](https://img.shields.io/github/forks/jakubie07/CVE-2026-1731.svg)

- [https://github.com/cybrdude/cve-2026-1731-scanner](https://github.com/cybrdude/cve-2026-1731-scanner) :  ![starts](https://img.shields.io/github/stars/cybrdude/cve-2026-1731-scanner.svg) ![forks](https://img.shields.io/github/forks/cybrdude/cve-2026-1731-scanner.svg)

- [https://github.com/hexissam/CVE-2026-1731](https://github.com/hexissam/CVE-2026-1731) :  ![starts](https://img.shields.io/github/stars/hexissam/CVE-2026-1731.svg) ![forks](https://img.shields.io/github/forks/hexissam/CVE-2026-1731.svg)

## CVE-2026-1729
 The AdForest theme for WordPress is vulnerable to authentication bypass in all versions up to, and including, 6.0.12. This is due to the plugin not properly verifying a user's identity prior to authenticating them through the 'sb_login_user_with_otp_fun' function. This makes it possible for unauthenticated attackers to log in as arbitrary users, including administrators.



- [https://github.com/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass](https://github.com/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass) :  ![starts](https://img.shields.io/github/stars/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass.svg) ![forks](https://img.shields.io/github/forks/ninjazan420/CVE-2026-1729-PoC-AdForest-WordPress-Authentication-Bypass.svg)

## CVE-2026-1668
 The web interface on multiple Omada switches does not adequately validate certain external inputs, which may lead to out-of-bound memory access when processing crafted requests.  Under specific conditions, this flaw may result in unintended command execution.brAn unauthenticated attacker with network access to the affected interface may cause memory corruption, service instability, or information disclosure.  Successful exploitation may allow remote code execution or denial-of-service.



- [https://github.com/tangrs/cve-2026-1668-poc](https://github.com/tangrs/cve-2026-1668-poc) :  ![starts](https://img.shields.io/github/stars/tangrs/cve-2026-1668-poc.svg) ![forks](https://img.shields.io/github/forks/tangrs/cve-2026-1668-poc.svg)

## CVE-2026-1657
 The EventPrime plugin for WordPress is vulnerable to unauthorized image file upload in all versions up to, and including, 4.2.8.4. This is due to the plugin registering the upload_file_media AJAX action as publicly accessible (nopriv-enabled) without implementing any authentication, authorization, or nonce verification despite a nonce being created. This makes it possible for unauthenticated attackers to upload image files to the WordPress uploads directory and create Media Library attachments via the ep_upload_file_media endpoint.



- [https://github.com/Vimash-Dilsara/-CVE-2026-1657](https://github.com/Vimash-Dilsara/-CVE-2026-1657) :  ![starts](https://img.shields.io/github/stars/Vimash-Dilsara/-CVE-2026-1657.svg) ![forks](https://img.shields.io/github/forks/Vimash-Dilsara/-CVE-2026-1657.svg)

- [https://github.com/d3kc4rt1/CVE-2026-1657](https://github.com/d3kc4rt1/CVE-2026-1657) :  ![starts](https://img.shields.io/github/stars/d3kc4rt1/CVE-2026-1657.svg) ![forks](https://img.shields.io/github/forks/d3kc4rt1/CVE-2026-1657.svg)

## CVE-2026-1581
 The wpForo Forum plugin for WordPress is vulnerable to time-based SQL Injection via the 'wpfob' parameter in all versions up to, and including, 2.4.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.



- [https://github.com/rootdirective-sec/CVE-2026-1581-Analysis-Lab](https://github.com/rootdirective-sec/CVE-2026-1581-Analysis-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-1581-Analysis-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-1581-Analysis-Lab.svg)

## CVE-2026-1560
 The Custom Block Builder – Lazy Blocks plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 4.2.0 via multiple functions in the 'LazyBlocks_Blocks' class. This makes it possible for authenticated attackers, with Contributor-level access and above, to execute code on the server.



- [https://github.com/Z3YR0xX/CVE-2026-1560-Authenticated-Remote-Code-Execution-in-Lazy-Blocks-4.2.0](https://github.com/Z3YR0xX/CVE-2026-1560-Authenticated-Remote-Code-Execution-in-Lazy-Blocks-4.2.0) :  ![starts](https://img.shields.io/github/stars/Z3YR0xX/CVE-2026-1560-Authenticated-Remote-Code-Execution-in-Lazy-Blocks-4.2.0.svg) ![forks](https://img.shields.io/github/forks/Z3YR0xX/CVE-2026-1560-Authenticated-Remote-Code-Execution-in-Lazy-Blocks-4.2.0.svg)

## CVE-2026-1555
 The WebStack theme for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the io_img_upload() function in all versions up to, and including, 1.2024. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2026-1555](https://github.com/Nxploited/CVE-2026-1555) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-1555.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-1555.svg)

## CVE-2026-1550
 A security flaw has been discovered in PHPGurukul Hospital Management System 1.0. Affected by this issue is some unknown functionality of the file /hms/hospital/docappsystem/adminviews.py of the component Admin Dashboard Page. Performing a manipulation results in improper authorization. Remote exploitation of the attack is possible. The exploit has been released to the public and may be used for attacks.



- [https://github.com/rsecroot/CVE-2026-1550](https://github.com/rsecroot/CVE-2026-1550) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2026-1550.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2026-1550.svg)

## CVE-2026-1529
 A flaw was found in Keycloak. An attacker can exploit this vulnerability by modifying the organization ID and target email within a legitimate invitation token's JSON Web Token (JWT) payload. This lack of cryptographic signature verification allows the attacker to successfully self-register into an unauthorized organization, leading to unauthorized access.



- [https://github.com/0x240x23elu/CVE-2026-1529](https://github.com/0x240x23elu/CVE-2026-1529) :  ![starts](https://img.shields.io/github/stars/0x240x23elu/CVE-2026-1529.svg) ![forks](https://img.shields.io/github/forks/0x240x23elu/CVE-2026-1529.svg)

- [https://github.com/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation](https://github.com/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation) :  ![starts](https://img.shields.io/github/stars/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation.svg) ![forks](https://img.shields.io/github/forks/ninjazan420/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation.svg)

- [https://github.com/ackemed/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation](https://github.com/ackemed/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation) :  ![starts](https://img.shields.io/github/stars/ackemed/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation.svg) ![forks](https://img.shields.io/github/forks/ackemed/CVE-2026-1529-PoC-keycloak-unauthorized-registration-via-improper-invitation-token-validation.svg)

## CVE-2026-1492
 The User Registration & Membership – Custom Registration Form Builder, Custom Login Form, User Profile, Content Restriction & Membership Plugin plugin for WordPress is vulnerable to improper privilege management in all versions up to, and including, 5.1.2. This is due to the plugin accepting a user-supplied role during membership registration without properly enforcing a server-side allowlist. This makes it possible for unauthenticated attackers to create administrator accounts by supplying a role value during membership registration.



- [https://github.com/Nxploited/CVE-2026-1492](https://github.com/Nxploited/CVE-2026-1492) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-1492.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-1492.svg)

- [https://github.com/the8frust/CVE-2026-1492](https://github.com/the8frust/CVE-2026-1492) :  ![starts](https://img.shields.io/github/stars/the8frust/CVE-2026-1492.svg) ![forks](https://img.shields.io/github/forks/the8frust/CVE-2026-1492.svg)

- [https://github.com/imad-z1/CVE-2026-1492-POC](https://github.com/imad-z1/CVE-2026-1492-POC) :  ![starts](https://img.shields.io/github/stars/imad-z1/CVE-2026-1492-POC.svg) ![forks](https://img.shields.io/github/forks/imad-z1/CVE-2026-1492-POC.svg)

## CVE-2026-1459
 A post-authentication command injection vulnerability in the TR-369 certificate download CGI program of the Zyxel VMG3625-T50B firmware versions through 5.50(ABPM.9.7)C0 could allow an authenticated attacker with administrator privileges to execute operating system (OS) commands on an affected device.



- [https://github.com/Toouch67/CVE-2026-1459-POC](https://github.com/Toouch67/CVE-2026-1459-POC) :  ![starts](https://img.shields.io/github/stars/Toouch67/CVE-2026-1459-POC.svg) ![forks](https://img.shields.io/github/forks/Toouch67/CVE-2026-1459-POC.svg)

## CVE-2026-1457
 An authenticated buffer handling flaw in TP-Link VIGI C385 V1 Web API lacking input sanitization, may allow memory corruption leading to remote code execution. Authenticated attackers may trigger buffer overflow and potentially execute arbitrary code with elevated privileges.



- [https://github.com/ii4gsp/CVE-2026-1457](https://github.com/ii4gsp/CVE-2026-1457) :  ![starts](https://img.shields.io/github/stars/ii4gsp/CVE-2026-1457.svg) ![forks](https://img.shields.io/github/forks/ii4gsp/CVE-2026-1457.svg)

## CVE-2026-1434
 Omega-PSIR is vulnerable to Reflected XSS via the lang parameter. An attacker can craft a malicious URL that, when opened, causes arbitrary JavaScript to execute in the victim’s browser.

This issue was fixed in 4.6.7.



- [https://github.com/lukasz-rybak/CVE-2026-1434](https://github.com/lukasz-rybak/CVE-2026-1434) :  ![starts](https://img.shields.io/github/stars/lukasz-rybak/CVE-2026-1434.svg) ![forks](https://img.shields.io/github/forks/lukasz-rybak/CVE-2026-1434.svg)

## CVE-2026-1424
 A vulnerability was identified in PHPGurukul News Portal 1.0. This affects an unknown part of the component Profile Pic Handler. The manipulation leads to unrestricted upload. It is possible to initiate the attack remotely. The exploit is publicly available and might be used.



- [https://github.com/rsecroot/CVE-2026-1424](https://github.com/rsecroot/CVE-2026-1424) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2026-1424.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2026-1424.svg)

## CVE-2026-1405
 The Slider Future plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'slider_future_handle_image_upload' function in all versions up to, and including, 1.0.5. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.



- [https://github.com/Nxploited/CVE-2026-1405](https://github.com/Nxploited/CVE-2026-1405) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-1405.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-1405.svg)

- [https://github.com/AnggaTechI/Mass-Scanner-CVE-2026-1405](https://github.com/AnggaTechI/Mass-Scanner-CVE-2026-1405) :  ![starts](https://img.shields.io/github/stars/AnggaTechI/Mass-Scanner-CVE-2026-1405.svg) ![forks](https://img.shields.io/github/forks/AnggaTechI/Mass-Scanner-CVE-2026-1405.svg)

## CVE-2026-1375
 The Tutor LMS – eLearning and online course solution plugin for WordPress is vulnerable to Insecure Direct Object References (IDOR) in all versions up to, and including, 3.9.5. This is due to missing object-level authorization checks in the `course_list_bulk_action()`, `bulk_delete_course()`, and `update_course_status()` functions. This makes it possible for authenticated attackers, with Tutor Instructor-level access and above, to modify or delete arbitrary courses they do not own by manipulating course IDs in bulk action requests.



- [https://github.com/d3kc4rt1/CVE-2026-1375](https://github.com/d3kc4rt1/CVE-2026-1375) :  ![starts](https://img.shields.io/github/stars/d3kc4rt1/CVE-2026-1375.svg) ![forks](https://img.shields.io/github/forks/d3kc4rt1/CVE-2026-1375.svg)

## CVE-2026-1357
 The Migration, Backup, Staging – WPvivid Backup & Migration plugin for WordPress is vulnerable to Unauthenticated Arbitrary File Upload in versions up to and including 0.9.123. This is due to improper error handling in the RSA decryption process combined with a lack of path sanitization when writing uploaded files. When the plugin fails to decrypt a session key using openssl_private_decrypt(), it does not terminate execution and instead passes the boolean false value to the phpseclib library's AES cipher initialization. The library treats this false value as a string of null bytes, allowing an attacker to encrypt a malicious payload using a predictable null-byte key. Additionally, the plugin accepts filenames from the decrypted payload without sanitization, enabling directory traversal to escape the protected backup directory. This makes it possible for unauthenticated attackers to upload arbitrary PHP files to publicly accessible directories and achieve Remote Code Execution via the wpvivid_action=send_to_site parameter.



- [https://github.com/LucasM0ntes/POC-CVE-2026-1357](https://github.com/LucasM0ntes/POC-CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/LucasM0ntes/POC-CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/LucasM0ntes/POC-CVE-2026-1357.svg)

- [https://github.com/halilkirazkaya/CVE-2026-1357](https://github.com/halilkirazkaya/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/halilkirazkaya/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/halilkirazkaya/CVE-2026-1357.svg)

- [https://github.com/cybertechajju/CVE-2026-1357-POC](https://github.com/cybertechajju/CVE-2026-1357-POC) :  ![starts](https://img.shields.io/github/stars/cybertechajju/CVE-2026-1357-POC.svg) ![forks](https://img.shields.io/github/forks/cybertechajju/CVE-2026-1357-POC.svg)

- [https://github.com/itsismarcos/Exploit-CVE-2026-1357](https://github.com/itsismarcos/Exploit-CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/itsismarcos/Exploit-CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/itsismarcos/Exploit-CVE-2026-1357.svg)

- [https://github.com/Nxploited/CVE-2026-1357](https://github.com/Nxploited/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-1357.svg)

- [https://github.com/0xBlackash/CVE-2026-1357](https://github.com/0xBlackash/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-1357.svg)

- [https://github.com/CVEs-Labs/CVE-2026-1357](https://github.com/CVEs-Labs/CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/CVEs-Labs/CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/CVEs-Labs/CVE-2026-1357.svg)

- [https://github.com/rootdirective-sec/CVE-2026-1357-Lab](https://github.com/rootdirective-sec/CVE-2026-1357-Lab) :  ![starts](https://img.shields.io/github/stars/rootdirective-sec/CVE-2026-1357-Lab.svg) ![forks](https://img.shields.io/github/forks/rootdirective-sec/CVE-2026-1357-Lab.svg)

- [https://github.com/masterwok/PoC-CVE-2026-1357](https://github.com/masterwok/PoC-CVE-2026-1357) :  ![starts](https://img.shields.io/github/stars/masterwok/PoC-CVE-2026-1357.svg) ![forks](https://img.shields.io/github/forks/masterwok/PoC-CVE-2026-1357.svg)

## CVE-2026-1340
 A code injection in Ivanti Endpoint Manager Mobile allowing attackers to achieve unauthenticated remote code execution.



- [https://github.com/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE](https://github.com/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE) :  ![starts](https://img.shields.io/github/stars/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE.svg) ![forks](https://img.shields.io/github/forks/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE.svg)

- [https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE](https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE) :  ![starts](https://img.shields.io/github/stars/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg) ![forks](https://img.shields.io/github/forks/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg)

## CVE-2026-1337
 Insufficient escaping of unicode characters in query log in Neo4j Enterprise and Community editions prior to 2026.01 can lead to XSS if the user opens the logs in a tool that treats them as HTML. There is no security impact on Neo4j products, but this advisory is released as a precaution to treat the logs as plain text if using versions prior to 2026.01.

Proof of concept exploit:  https://github.com/JoakimBulow/CVE-2026-1337



- [https://github.com/JoakimBulow/CVE-2026-1337](https://github.com/JoakimBulow/CVE-2026-1337) :  ![starts](https://img.shields.io/github/stars/JoakimBulow/CVE-2026-1337.svg) ![forks](https://img.shields.io/github/forks/JoakimBulow/CVE-2026-1337.svg)

## CVE-2026-1312
 An issue was discovered in 6.0 before 6.0.2, 5.2 before 5.2.11, and 4.2 before 4.2.28.
`.QuerySet.order_by()` is subject to SQL injection in column aliases containing periods when the same alias is, using a suitably crafted dictionary, with dictionary expansion, used in `FilteredRelation`.
Earlier, unsupported Django series (such as 5.0.x, 4.1.x, and 3.2.x) were not evaluated and may also be affected.
Django would like to thank Solomon Kebede for reporting this issue.



- [https://github.com/sw0rd1ight/CVE-2026-1312](https://github.com/sw0rd1ight/CVE-2026-1312) :  ![starts](https://img.shields.io/github/stars/sw0rd1ight/CVE-2026-1312.svg) ![forks](https://img.shields.io/github/forks/sw0rd1ight/CVE-2026-1312.svg)

- [https://github.com/alpinine/CVE-2026-1312-Testing](https://github.com/alpinine/CVE-2026-1312-Testing) :  ![starts](https://img.shields.io/github/stars/alpinine/CVE-2026-1312-Testing.svg) ![forks](https://img.shields.io/github/forks/alpinine/CVE-2026-1312-Testing.svg)

## CVE-2026-1306
 The midi-Synth plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type and file extension validation in the 'export' AJAX action in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible granted the attacker can obtain a valid nonce. The nonce is exposed in frontend JavaScript making it trivially accessible to unauthenticated attackers.



- [https://github.com/murrez/CVE-2026-1306](https://github.com/murrez/CVE-2026-1306) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-1306.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-1306.svg)

## CVE-2026-1281
 A code injection in Ivanti Endpoint Manager Mobile allowing attackers to achieve unauthenticated remote code execution.



- [https://github.com/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE](https://github.com/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE) :  ![starts](https://img.shields.io/github/stars/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE.svg) ![forks](https://img.shields.io/github/forks/MehdiLeDeaut/CVE-2026-1281-Ivanti-EPMM-RCE.svg)

- [https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE](https://github.com/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE) :  ![starts](https://img.shields.io/github/stars/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg) ![forks](https://img.shields.io/github/forks/YunfeiGE18/CVE-2026-1281-CVE-2026-1340-Ivanti-EPMM-RCE.svg)

## CVE-2026-1208
 The Friendly Functions for Welcart plugin for WordPress is vulnerable to Cross-Site Request Forgery in all versions up to, and including, 1.2.5. This is due to missing or incorrect nonce validation on the settings page. This makes it possible for unauthenticated attackers to update plugin settings via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.



- [https://github.com/SnailSploit/CVE-2026-1208](https://github.com/SnailSploit/CVE-2026-1208) :  ![starts](https://img.shields.io/github/stars/SnailSploit/CVE-2026-1208.svg) ![forks](https://img.shields.io/github/forks/SnailSploit/CVE-2026-1208.svg)

## CVE-2026-1207
 An issue was discovered in 6.0 before 6.0.2, 5.2 before 5.2.11, and 4.2 before 4.2.28.
Raster lookups on ``RasterField`` (only implemented on PostGIS) allows remote attackers to inject SQL via the band index parameter.
Earlier, unsupported Django series (such as 5.0.x, 4.1.x, and 3.2.x) were not evaluated and may also be affected.
Django would like to thank Tarek Nakkouch for reporting this issue.



- [https://github.com/sw0rd1ight/CVE-2026-1207](https://github.com/sw0rd1ight/CVE-2026-1207) :  ![starts](https://img.shields.io/github/stars/sw0rd1ight/CVE-2026-1207.svg) ![forks](https://img.shields.io/github/forks/sw0rd1ight/CVE-2026-1207.svg)

## CVE-2026-1107
 A weakness has been identified in EyouCMS up to 1.7.1/5.0. Impacted is the function check_userinfo of the file Diyajax.php of the component Member Avatar Handler. Executing a manipulation of the argument viewfile can lead to unrestricted upload. The attack may be performed from remote. The exploit has been made available to the public and could be used for attacks. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/Iniivan13/CVE-2026-1107](https://github.com/Iniivan13/CVE-2026-1107) :  ![starts](https://img.shields.io/github/stars/Iniivan13/CVE-2026-1107.svg) ![forks](https://img.shields.io/github/forks/Iniivan13/CVE-2026-1107.svg)

## CVE-2026-1056
 The Snow Monkey Forms plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the 'generate_user_dirpath' function in all versions up to, and including, 12.0.3. This makes it possible for unauthenticated attackers to delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php).



- [https://github.com/ch4r0nn/CVE-2026-1056-POC](https://github.com/ch4r0nn/CVE-2026-1056-POC) :  ![starts](https://img.shields.io/github/stars/ch4r0nn/CVE-2026-1056-POC.svg) ![forks](https://img.shields.io/github/forks/ch4r0nn/CVE-2026-1056-POC.svg)

## CVE-2026-0920
 The LA-Studio Element Kit for Elementor plugin for WordPress is vulnerable to Administrative User Creation in all versions up to, and including, 1.5.6.3. This is due to the 'ajax_register_handle' function not restricting what user roles a user can register with. This makes it possible for unauthenticated attackers to supply the 'lakit_bkrole' parameter during registration and gain administrator access to the site.



- [https://github.com/John-doe-code-a11/CVE-2026-0920](https://github.com/John-doe-code-a11/CVE-2026-0920) :  ![starts](https://img.shields.io/github/stars/John-doe-code-a11/CVE-2026-0920.svg) ![forks](https://img.shields.io/github/forks/John-doe-code-a11/CVE-2026-0920.svg)

- [https://github.com/O99099O/By-Poloss..-..CVE-2026-0920](https://github.com/O99099O/By-Poloss..-..CVE-2026-0920) :  ![starts](https://img.shields.io/github/stars/O99099O/By-Poloss..-..CVE-2026-0920.svg) ![forks](https://img.shields.io/github/forks/O99099O/By-Poloss..-..CVE-2026-0920.svg)

- [https://github.com/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit](https://github.com/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit) :  ![starts](https://img.shields.io/github/stars/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit.svg) ![forks](https://img.shields.io/github/forks/Galaxy-sc/CVE-2026-0920-WordPress-LA-Studio-Exploit.svg)

- [https://github.com/Nxploited/CVE-2026-0920-](https://github.com/Nxploited/CVE-2026-0920-) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2026-0920-.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2026-0920-.svg)

## CVE-2026-0915
 Calling getnetbyaddr or getnetbyaddr_r with a configured nsswitch.conf that specifies the library's DNS backend for networks and queries for a zero-valued network in the GNU C Library version 2.0 to version 2.42 can leak stack contents to the configured DNS resolver.



- [https://github.com/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0](https://github.com/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0) :  ![starts](https://img.shields.io/github/stars/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0.svg) ![forks](https://img.shields.io/github/forks/cyberwulfy200-dev/CVE-2026-0915-json-Patch.-V2.0.svg)

## CVE-2026-0911
 The Hustle – Email Marketing, Lead Generation, Optins, Popups plugin for WordPress is vulnerable to arbitrary file uploads due to incorrect file type validation in the action_import_module() function in all versions up to, and including, 7.8.9.2. This makes it possible for authenticated attackers, with a lower-privileged role (e.g., Subscriber-level access and above), to upload arbitrary files on the affected site's server which may make remote code execution possible. Successful exploitation requires an admin to grant Hustle module permissions (or module edit access) to the low-privileged user so they can access the Hustle admin page and obtain the required nonce.



- [https://github.com/murrez/CVE-2026-0911](https://github.com/murrez/CVE-2026-0911) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-0911.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-0911.svg)

## CVE-2026-0897
 Allocation of Resources Without Limits or Throttling in the HDF5 weight loading component in Google Keras 3.0.0 through 3.13.0 on all platforms allows a remote attacker to cause a Denial of Service (DoS) through memory exhaustion and a crash of the Python interpreter via a crafted .keras archive containing a valid model.weights.h5 file whose dataset declares an extremely large shape.



- [https://github.com/HyperPS/CVE-2026-0897](https://github.com/HyperPS/CVE-2026-0897) :  ![starts](https://img.shields.io/github/stars/HyperPS/CVE-2026-0897.svg) ![forks](https://img.shields.io/github/forks/HyperPS/CVE-2026-0897.svg)

## CVE-2026-0866
 After the publication of the PoC by the researcher and further analysis, we have determined that this issue does not constitute a valid vulnerability. The technique described is an obfuscation method and does not bypass or impact any implicit or explicit security controls.



- [https://github.com/mdshoaibuddinchanda/zombieguard](https://github.com/mdshoaibuddinchanda/zombieguard) :  ![starts](https://img.shields.io/github/stars/mdshoaibuddinchanda/zombieguard.svg) ![forks](https://img.shields.io/github/forks/mdshoaibuddinchanda/zombieguard.svg)

## CVE-2026-0848
 NLTK versions =3.9.2 are vulnerable to arbitrary code execution due to improper input validation in the StanfordSegmenter module. The module dynamically loads external Java .jar files without verification or sandboxing. An attacker can supply or replace the JAR file, enabling the execution of arbitrary Java bytecode at import time. This vulnerability can be exploited through methods such as model poisoning, MITM attacks, or dependency poisoning, leading to remote code execution. The issue arises from the direct execution of the JAR file via subprocess with unvalidated classpath input, allowing malicious classes to execute when loaded by the JVM.



- [https://github.com/HyperPS/CVE-2026-0848](https://github.com/HyperPS/CVE-2026-0848) :  ![starts](https://img.shields.io/github/stars/HyperPS/CVE-2026-0848.svg) ![forks](https://img.shields.io/github/forks/HyperPS/CVE-2026-0848.svg)

- [https://github.com/fevar54/CVE-2026-0848-Scanner---Herramienta-de-Detecci-n](https://github.com/fevar54/CVE-2026-0848-Scanner---Herramienta-de-Detecci-n) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-0848-Scanner---Herramienta-de-Detecci-n.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-0848-Scanner---Herramienta-de-Detecci-n.svg)

- [https://github.com/fevar54/CVE-2026-0848-PoC-Improper-Input-Validation](https://github.com/fevar54/CVE-2026-0848-PoC-Improper-Input-Validation) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-0848-PoC-Improper-Input-Validation.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-0848-PoC-Improper-Input-Validation.svg)

## CVE-2026-0847
 A vulnerability in NLTK versions up to and including 3.9.2 allows arbitrary file read via path traversal in multiple CorpusReader classes, including WordListCorpusReader, TaggedCorpusReader, and BracketParseCorpusReader. These classes fail to properly sanitize or validate file paths, enabling attackers to traverse directories and access sensitive files on the server. This issue is particularly critical in scenarios where user-controlled file inputs are processed, such as in machine learning APIs, chatbots, or NLP pipelines. Exploitation of this vulnerability can lead to unauthorized access to sensitive files, including system files, SSH private keys, and API tokens, and may potentially escalate to remote code execution when combined with other vulnerabilities.



- [https://github.com/HyperPS/CVE-2026-0847](https://github.com/HyperPS/CVE-2026-0847) :  ![starts](https://img.shields.io/github/stars/HyperPS/CVE-2026-0847.svg) ![forks](https://img.shields.io/github/forks/HyperPS/CVE-2026-0847.svg)

## CVE-2026-0842
 A flaw has been found in Flycatcher Toys smART Sketcher up to 2.0. This affects an unknown part of the component Bluetooth Low Energy Interface. This manipulation causes missing authentication. The attack can only be done within the local network. The exploit has been published and may be used. The vendor was contacted early about this disclosure but did not respond in any way.



- [https://github.com/davidrxchester/smart-sketcher-upload](https://github.com/davidrxchester/smart-sketcher-upload) :  ![starts](https://img.shields.io/github/stars/davidrxchester/smart-sketcher-upload.svg) ![forks](https://img.shields.io/github/forks/davidrxchester/smart-sketcher-upload.svg)

## CVE-2026-0834
 Logic vulnerability in TP-Link Archer C20 v5, 6.0, Archer AX53 v1.0 and TL-WR841N v13 (TDDP module) allows unauthenticated adjacent attackers to execute administrative commands including factory reset and device reboot without credentials. Attackers on the adjacent network can remotely trigger factory resets and reboots without credentials, causing configuration loss and interruption of device availability.

This issue affects Archer C20 v6.0  V6_251031, Archer C20 v5 EU_V5_260317 or  US_V5_260419


Archer AX53 v1.0  

V1_251215



TL-WR841N v13  0.9.1 Build 20231120 Rel.62366



- [https://github.com/mattgsys/CVE-2026-0834](https://github.com/mattgsys/CVE-2026-0834) :  ![starts](https://img.shields.io/github/stars/mattgsys/CVE-2026-0834.svg) ![forks](https://img.shields.io/github/forks/mattgsys/CVE-2026-0834.svg)

## CVE-2026-0827
 During an internal security assessment, a potential vulnerability was discovered in Lenovo Diagnostics and the HardwareScanAddin used in Lenovo Vantage that, during installation or when using hardware scan, could allow a local authenticated user to perform an arbitrary file write with elevated privileges.



- [https://github.com/ZeroMemoryEx/CVE-2026-0827](https://github.com/ZeroMemoryEx/CVE-2026-0827) :  ![starts](https://img.shields.io/github/stars/ZeroMemoryEx/CVE-2026-0827.svg) ![forks](https://img.shields.io/github/forks/ZeroMemoryEx/CVE-2026-0827.svg)

## CVE-2026-0770
 Langflow exec_globals Inclusion of Functionality from Untrusted Control Sphere Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Langflow. Authentication is not required to exploit this vulnerability.

The specific flaw exists within the handling of the exec_globals parameter provided to the validate endpoint. The issue results from the inclusion of a resource from an untrusted control sphere. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-27325.



- [https://github.com/affix/CVE-2026-0770-PoC](https://github.com/affix/CVE-2026-0770-PoC) :  ![starts](https://img.shields.io/github/stars/affix/CVE-2026-0770-PoC.svg) ![forks](https://img.shields.io/github/forks/affix/CVE-2026-0770-PoC.svg)

- [https://github.com/0xBlackash/CVE-2026-0770](https://github.com/0xBlackash/CVE-2026-0770) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-0770.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-0770.svg)

- [https://github.com/0xgh057r3c0n/CVE-2026-0770](https://github.com/0xgh057r3c0n/CVE-2026-0770) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2026-0770.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2026-0770.svg)

- [https://github.com/Yetazyyy/CVE-2026-0770](https://github.com/Yetazyyy/CVE-2026-0770) :  ![starts](https://img.shields.io/github/stars/Yetazyyy/CVE-2026-0770.svg) ![forks](https://img.shields.io/github/forks/Yetazyyy/CVE-2026-0770.svg)

## CVE-2026-0766
 Open WebUI load_tool_module_by_id Command Injection Remote Code Execution Vulnerability. This vulnerability allows remote attackers to execute arbitrary code on affected installations of Open WebUI. Authentication is required to exploit this vulnerability.

The specific flaw exists within the load_tool_module_by_id function. The issue results from the lack of proper validation of a user-supplied string before using it to execute Python code. An attacker can leverage this vulnerability to execute code in the context of the service account. Was ZDI-CAN-28257.



- [https://github.com/bitt0n/CVE-2026-0766](https://github.com/bitt0n/CVE-2026-0766) :  ![starts](https://img.shields.io/github/stars/bitt0n/CVE-2026-0766.svg) ![forks](https://img.shields.io/github/forks/bitt0n/CVE-2026-0766.svg)

## CVE-2026-0745
 The User Language Switch plugin for WordPress is vulnerable to Server-Side Request Forgery in all versions up to, and including, 1.6.10 due to missing URL validation on the 'download_language()' function. This makes it possible for authenticated attackers, with Administrator-level access and above, to make web requests to arbitrary locations originating from the web application and can be used to query and modify information from internal services.



- [https://github.com/NetVanguard-cmd/CVE-2026-0745](https://github.com/NetVanguard-cmd/CVE-2026-0745) :  ![starts](https://img.shields.io/github/stars/NetVanguard-cmd/CVE-2026-0745.svg) ![forks](https://img.shields.io/github/forks/NetVanguard-cmd/CVE-2026-0745.svg)

## CVE-2026-0740
 The Ninja Forms - File Uploads plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'NF_FU_AJAX_Controllers_Uploads::handle_upload' function in all versions up to, and including, 3.3.26. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible. Note: The vulnerability was partially patched in version 3.3.25 and fully patched in version 3.3.27.



- [https://github.com/0xgh057r3c0n/CVE-2026-0740](https://github.com/0xgh057r3c0n/CVE-2026-0740) :  ![starts](https://img.shields.io/github/stars/0xgh057r3c0n/CVE-2026-0740.svg) ![forks](https://img.shields.io/github/forks/0xgh057r3c0n/CVE-2026-0740.svg)

- [https://github.com/whattheslime/CVE-2026-0740](https://github.com/whattheslime/CVE-2026-0740) :  ![starts](https://img.shields.io/github/stars/whattheslime/CVE-2026-0740.svg) ![forks](https://img.shields.io/github/forks/whattheslime/CVE-2026-0740.svg)

- [https://github.com/murrez/CVE-2026-0740](https://github.com/murrez/CVE-2026-0740) :  ![starts](https://img.shields.io/github/stars/murrez/CVE-2026-0740.svg) ![forks](https://img.shields.io/github/forks/murrez/CVE-2026-0740.svg)

- [https://github.com/xShadow-Here/CVE-2026-0740](https://github.com/xShadow-Here/CVE-2026-0740) :  ![starts](https://img.shields.io/github/stars/xShadow-Here/CVE-2026-0740.svg) ![forks](https://img.shields.io/github/forks/xShadow-Here/CVE-2026-0740.svg)

- [https://github.com/BastianXploited/CVE-2026-0740](https://github.com/BastianXploited/CVE-2026-0740) :  ![starts](https://img.shields.io/github/stars/BastianXploited/CVE-2026-0740.svg) ![forks](https://img.shields.io/github/forks/BastianXploited/CVE-2026-0740.svg)

## CVE-2026-0730
 A flaw has been found in PHPGurukul Staff Leave Management System 1.0. The affected element is the function ADD_STAFF/UPDATE_STAFF of the file /staffleave/slms/slms/adminviews.py of the component SVG File Handler. Executing a manipulation of the argument profile_pic can lead to cross site scripting. The attack can be executed remotely. The exploit has been published and may be used.



- [https://github.com/rsecroot/CVE-2026-0730](https://github.com/rsecroot/CVE-2026-0730) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2026-0730.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2026-0730.svg)

## CVE-2026-0709
 Some Hikvision Wireless Access Points are vulnerable to authenticated command execution due to insufficient input validation. Attackers with valid credentials can exploit this flaw by sending crafted packets containing malicious commands to affected devices, leading to arbitrary command execution.



- [https://github.com/SnipersMaster/CVE-2026-0709](https://github.com/SnipersMaster/CVE-2026-0709) :  ![starts](https://img.shields.io/github/stars/SnipersMaster/CVE-2026-0709.svg) ![forks](https://img.shields.io/github/forks/SnipersMaster/CVE-2026-0709.svg)

## CVE-2026-0651
 A path traversal vulnerability was identified TP-Link Tapo C260 v1, D235 v1 and C520WS v2.6 within the HTTP server’s handling of GET requests. The server performs path normalization before fully decoding URL encoded input and falls back to using the raw path when normalization fails. An attacker can exploit this logic flaw by supplying crafted, URL encoded traversal sequences that bypass directory restrictions and allow access to files outside the intended web root. 

Successful exploitation may allow authenticated attackers to get disclosure of sensitive system files and credentials, while unauthenticated attackers may gain access to non-sensitive static assets.



- [https://github.com/l0lsec/tapo-c260-rce](https://github.com/l0lsec/tapo-c260-rce) :  ![starts](https://img.shields.io/github/stars/l0lsec/tapo-c260-rce.svg) ![forks](https://img.shields.io/github/forks/l0lsec/tapo-c260-rce.svg)

## CVE-2026-0628
 Insufficient policy enforcement in WebView tag in Google Chrome prior to 143.0.7499.192 allowed an attacker who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via a crafted Chrome Extension. (Chromium security severity: High)



- [https://github.com/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation](https://github.com/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation.svg)

- [https://github.com/fevar54/CVE-2026-0628-POC](https://github.com/fevar54/CVE-2026-0628-POC) :  ![starts](https://img.shields.io/github/stars/fevar54/CVE-2026-0628-POC.svg) ![forks](https://img.shields.io/github/forks/fevar54/CVE-2026-0628-POC.svg)

## CVE-2026-0622
 Open 5GS WebUI uses a hard-coded JWT signing key (change-me) whenever the environment variable JWT_SECRET_KEY is unset



- [https://github.com/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor) :  ![starts](https://img.shields.io/github/stars/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor.svg) ![forks](https://img.shields.io/github/forks/cyberdudebivash/CYBERDUDEBIVASH-5G-Core-Key-Rotation-Ghost-Admin-Auditor.svg)

## CVE-2026-0603
 A flaw was found in Hibernate. A remote attacker with low privileges could exploit a second-order SQL injection vulnerability by providing specially crafted, unsanitized non-alphanumeric characters in the ID column when the InlineIdsOrClauseBuilder is used. This could lead to sensitive information disclosure, such as reading system files, and allow for data manipulation or deletion within the application's database, resulting in an application level denial of service.



- [https://github.com/EQSTLab/CVE-2026-0603](https://github.com/EQSTLab/CVE-2026-0603) :  ![starts](https://img.shields.io/github/stars/EQSTLab/CVE-2026-0603.svg) ![forks](https://img.shields.io/github/forks/EQSTLab/CVE-2026-0603.svg)

## CVE-2026-0594
 The List Site Contributors plugin for WordPress is vulnerable to Reflected Cross-Site Scripting via the 'alpha' parameter in versions up to, and including, 1.1.8 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.



- [https://github.com/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit](https://github.com/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit) :  ![starts](https://img.shields.io/github/stars/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit.svg) ![forks](https://img.shields.io/github/forks/m4sh-wacker/CVE-2026-0594-ListSiteContributors-Plugin-Exploit.svg)

## CVE-2026-0547
 A vulnerability was found in PHPGurukul Online Course Registration up to 3.1. This issue affects some unknown processing of the file /admin/edit-student-profile.php of the component Student Registration Page. The manipulation of the argument photo results in unrestricted upload. The attack may be launched remotely. The exploit has been made public and could be used.



- [https://github.com/rsecroot/CVE-2026-0547](https://github.com/rsecroot/CVE-2026-0547) :  ![starts](https://img.shields.io/github/stars/rsecroot/CVE-2026-0547.svg) ![forks](https://img.shields.io/github/forks/rsecroot/CVE-2026-0547.svg)

## CVE-2026-0300
 A buffer overflow vulnerability in the User-ID™ Authentication Portal (aka Captive Portal) service of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the PA-Series and VM-Series firewalls by sending specially crafted packets. 

The risk of this issue is greatly reduced if you secure access to the User-ID™ Authentication Portal per the  best practice guidelines https://knowledgebase.paloaltonetworks.com/KCSArticleDetail  by restricting access to only trusted internal IP addresses.

Prisma Access, Cloud NGFW and Panorama appliances are not impacted by this vulnerability.



- [https://github.com/p3Nt3st3r-sTAr/CVE-2026-0300-POC](https://github.com/p3Nt3st3r-sTAr/CVE-2026-0300-POC) :  ![starts](https://img.shields.io/github/stars/p3Nt3st3r-sTAr/CVE-2026-0300-POC.svg) ![forks](https://img.shields.io/github/forks/p3Nt3st3r-sTAr/CVE-2026-0300-POC.svg)

- [https://github.com/qassam-315/PAN-OS-User-ID-Buffer-Overflow-PoC](https://github.com/qassam-315/PAN-OS-User-ID-Buffer-Overflow-PoC) :  ![starts](https://img.shields.io/github/stars/qassam-315/PAN-OS-User-ID-Buffer-Overflow-PoC.svg) ![forks](https://img.shields.io/github/forks/qassam-315/PAN-OS-User-ID-Buffer-Overflow-PoC.svg)

- [https://github.com/mr-r3b00t/CVE-2026-0300](https://github.com/mr-r3b00t/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/mr-r3b00t/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/mr-r3b00t/CVE-2026-0300.svg)

- [https://github.com/0xBlackash/CVE-2026-0300](https://github.com/0xBlackash/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-0300.svg)

- [https://github.com/shizuku198411/CVE-2026-0300](https://github.com/shizuku198411/CVE-2026-0300) :  ![starts](https://img.shields.io/github/stars/shizuku198411/CVE-2026-0300.svg) ![forks](https://img.shields.io/github/forks/shizuku198411/CVE-2026-0300.svg)

- [https://github.com/bannned-bit/CVE-2026-0300-PANOS](https://github.com/bannned-bit/CVE-2026-0300-PANOS) :  ![starts](https://img.shields.io/github/stars/bannned-bit/CVE-2026-0300-PANOS.svg) ![forks](https://img.shields.io/github/forks/bannned-bit/CVE-2026-0300-PANOS.svg)

- [https://github.com/TailwindRG/cve-2026-0300-audit](https://github.com/TailwindRG/cve-2026-0300-audit) :  ![starts](https://img.shields.io/github/stars/TailwindRG/cve-2026-0300-audit.svg) ![forks](https://img.shields.io/github/forks/TailwindRG/cve-2026-0300-audit.svg)

## CVE-2026-0227
 A vulnerability in Palo Alto Networks PAN-OS software enables an unauthenticated attacker to cause a denial of service (DoS) to the firewall. Repeated attempts to trigger this issue results in the firewall entering into maintenance mode.



- [https://github.com/TeeyaR/CVE-2026-0227-Palo-Alto](https://github.com/TeeyaR/CVE-2026-0227-Palo-Alto) :  ![starts](https://img.shields.io/github/stars/TeeyaR/CVE-2026-0227-Palo-Alto.svg) ![forks](https://img.shields.io/github/forks/TeeyaR/CVE-2026-0227-Palo-Alto.svg)

- [https://github.com/CkAbhijit/CVE-2026-0227-Advanced-Scanner](https://github.com/CkAbhijit/CVE-2026-0227-Advanced-Scanner) :  ![starts](https://img.shields.io/github/stars/CkAbhijit/CVE-2026-0227-Advanced-Scanner.svg) ![forks](https://img.shields.io/github/forks/CkAbhijit/CVE-2026-0227-Advanced-Scanner.svg)

## CVE-2026-0073
 In adbd_tls_verify_cert of auth.cpp, there is a possible bypass of wireless ADB mutual authentication due to a logic error in the code. This could lead to remote (proximal/adjacent) code execution as the shell user with no additional execution privileges needed. User interaction is not needed for exploitation.



- [https://github.com/SecTestAnnaQuinn/CVE-2026-0073-Android-adbd-authentication-bypass-POC](https://github.com/SecTestAnnaQuinn/CVE-2026-0073-Android-adbd-authentication-bypass-POC) :  ![starts](https://img.shields.io/github/stars/SecTestAnnaQuinn/CVE-2026-0073-Android-adbd-authentication-bypass-POC.svg) ![forks](https://img.shields.io/github/forks/SecTestAnnaQuinn/CVE-2026-0073-Android-adbd-authentication-bypass-POC.svg)

- [https://github.com/adityatelange/poc-CVE-2026-0073](https://github.com/adityatelange/poc-CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/adityatelange/poc-CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/adityatelange/poc-CVE-2026-0073.svg)

- [https://github.com/MartinPSDev/CVE-2026-0073-Android-ADBD-bypass-POC](https://github.com/MartinPSDev/CVE-2026-0073-Android-ADBD-bypass-POC) :  ![starts](https://img.shields.io/github/stars/MartinPSDev/CVE-2026-0073-Android-ADBD-bypass-POC.svg) ![forks](https://img.shields.io/github/forks/MartinPSDev/CVE-2026-0073-Android-ADBD-bypass-POC.svg)

- [https://github.com/novaek/CVE-2026-0073-Research](https://github.com/novaek/CVE-2026-0073-Research) :  ![starts](https://img.shields.io/github/stars/novaek/CVE-2026-0073-Research.svg) ![forks](https://img.shields.io/github/forks/novaek/CVE-2026-0073-Research.svg)

- [https://github.com/0xBlackash/CVE-2026-0073](https://github.com/0xBlackash/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-0073.svg)

- [https://github.com/devtint/CVE-2026-0073](https://github.com/devtint/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/devtint/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/devtint/CVE-2026-0073.svg)

- [https://github.com/unnaim/adbHijacker](https://github.com/unnaim/adbHijacker) :  ![starts](https://img.shields.io/github/stars/unnaim/adbHijacker.svg) ![forks](https://img.shields.io/github/forks/unnaim/adbHijacker.svg)

- [https://github.com/CryptReaper12/CVE-2026-0073](https://github.com/CryptReaper12/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/CryptReaper12/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/CryptReaper12/CVE-2026-0073.svg)

- [https://github.com/ByteWraith1/CVE-2026-0073](https://github.com/ByteWraith1/CVE-2026-0073) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-0073.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-0073.svg)

## CVE-2026-0047
 In dumpBitmapsProto of ActivityManagerService.java, there is a possible way for an app to access private information due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.



- [https://github.com/mobilehackinglab/CVE-2026-0047-poc](https://github.com/mobilehackinglab/CVE-2026-0047-poc) :  ![starts](https://img.shields.io/github/stars/mobilehackinglab/CVE-2026-0047-poc.svg) ![forks](https://img.shields.io/github/forks/mobilehackinglab/CVE-2026-0047-poc.svg)

## CVE-2026-0006
 In multiple locations, there is a possible out of bounds read and write due to a heap buffer overflow. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.



- [https://github.com/mobilehackinglab/CVE-2026-0006-openapv-poc](https://github.com/mobilehackinglab/CVE-2026-0006-openapv-poc) :  ![starts](https://img.shields.io/github/stars/mobilehackinglab/CVE-2026-0006-openapv-poc.svg) ![forks](https://img.shields.io/github/forks/mobilehackinglab/CVE-2026-0006-openapv-poc.svg)

- [https://github.com/aydin5245/cve-2026-0006](https://github.com/aydin5245/cve-2026-0006) :  ![starts](https://img.shields.io/github/stars/aydin5245/cve-2026-0006.svg) ![forks](https://img.shields.io/github/forks/aydin5245/cve-2026-0006.svg)
