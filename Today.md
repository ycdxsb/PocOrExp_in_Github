# Update 2021-08-28
## CVE-2017-13089
 The http.c:skip_short_body() function is called in some circumstances, such as when processing redirects. When the response is sent chunked in wget before 1.19.2, the chunk parser uses strtol() to read each chunk's length, but doesn't check that the chunk length is a non-negative number. The code then tries to skip the chunk in pieces of 512 bytes by using the MIN() macro, but ends up passing the negative chunk length to connect.c:fd_read(). As fd_read() takes an int argument, the high 32 bits of the chunk length are discarded, leaving fd_read() with a completely attacker controlled length argument.

- [https://github.com/r1b/CVE-2017-13089](https://github.com/r1b/CVE-2017-13089) :  ![starts](https://img.shields.io/github/stars/r1b/CVE-2017-13089.svg) ![forks](https://img.shields.io/github/forks/r1b/CVE-2017-13089.svg)


## CVE-2016-6515
 The auth_password function in auth-passwd.c in sshd in OpenSSH before 7.3 does not limit password lengths for password authentication, which allows remote attackers to cause a denial of service (crypt CPU consumption) via a long string.

- [https://github.com/jptr218/openssh_dos](https://github.com/jptr218/openssh_dos) :  ![starts](https://img.shields.io/github/stars/jptr218/openssh_dos.svg) ![forks](https://img.shields.io/github/forks/jptr218/openssh_dos.svg)


## CVE-2016-3088
 The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.

- [https://github.com/pudiding/CVE-2016-3088](https://github.com/pudiding/CVE-2016-3088) :  ![starts](https://img.shields.io/github/stars/pudiding/CVE-2016-3088.svg) ![forks](https://img.shields.io/github/forks/pudiding/CVE-2016-3088.svg)


## CVE-2004-2687
 distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.

- [https://github.com/1nf1n17yk1ng/distccd_rce_CVE-2004-2687](https://github.com/1nf1n17yk1ng/distccd_rce_CVE-2004-2687) :  ![starts](https://img.shields.io/github/stars/1nf1n17yk1ng/distccd_rce_CVE-2004-2687.svg) ![forks](https://img.shields.io/github/forks/1nf1n17yk1ng/distccd_rce_CVE-2004-2687.svg)

