# Update 2021-06-30
## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/ThomTiber/patches](https://github.com/ThomTiber/patches) :  ![starts](https://img.shields.io/github/stars/ThomTiber/patches.svg) ![forks](https://img.shields.io/github/forks/ThomTiber/patches.svg)


## CVE-2020-15368
 AsrDrv103.sys in the ASRock RGB Driver does not properly restrict access from user space, as demonstrated by triggering a triple fault via a request to zero CR3.

- [https://github.com/stong/CVE-2020-15368](https://github.com/stong/CVE-2020-15368) :  ![starts](https://img.shields.io/github/stars/stong/CVE-2020-15368.svg) ![forks](https://img.shields.io/github/forks/stong/CVE-2020-15368.svg)


## CVE-2019-12725
 Zeroshell 3.9.0 is prone to a remote command execution vulnerability. Specifically, this issue occurs because the web application mishandles a few HTTP parameters. An unauthenticated attacker can exploit this issue by injecting OS commands inside the vulnerable parameters.

- [https://github.com/MzzdToT/CVE-2019-12725](https://github.com/MzzdToT/CVE-2019-12725) :  ![starts](https://img.shields.io/github/stars/MzzdToT/CVE-2019-12725.svg) ![forks](https://img.shields.io/github/forks/MzzdToT/CVE-2019-12725.svg)


## CVE-2019-9787
 WordPress before 5.1.1 does not properly filter comment content, leading to Remote Code Execution by unauthenticated users in a default configuration. This occurs because CSRF protection is mishandled, and because Search Engine Optimization of A elements is performed incorrectly, leading to XSS. The XSS results in administrative access, which allows arbitrary changes to .php files. This is related to wp-admin/includes/ajax-actions.php and wp-includes/comment.php.

- [https://github.com/dexXxed/CVE-2019-9787](https://github.com/dexXxed/CVE-2019-9787) :  ![starts](https://img.shields.io/github/stars/dexXxed/CVE-2019-9787.svg) ![forks](https://img.shields.io/github/forks/dexXxed/CVE-2019-9787.svg)


## CVE-2019-6447
 The ES File Explorer File Manager application through 4.1.9.7.4 for Android allows remote attackers to read arbitrary files or execute applications via TCP port 59777 requests on the local Wi-Fi network. This TCP port remains open after the ES application has been launched once, and responds to unauthenticated application/json data over HTTP.

- [https://github.com/N3H4L/CVE-2019-6447](https://github.com/N3H4L/CVE-2019-6447) :  ![starts](https://img.shields.io/github/stars/N3H4L/CVE-2019-6447.svg) ![forks](https://img.shields.io/github/forks/N3H4L/CVE-2019-6447.svg)

