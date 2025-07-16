# Update 2025-07-16
## CVE-2025-52488
 DNN (formerly DotNetNuke) is an open-source web content management platform (CMS) in the Microsoft ecosystem. In versions 6.0.0 to before 10.0.1, DNN.PLATFORM allows a specially crafted series of malicious interaction to potentially expose NTLM hashes to a third party SMB server. This issue has been patched in version 10.0.1.

- [https://github.com/SystemVll/CVE-2025-52488](https://github.com/SystemVll/CVE-2025-52488) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2025-52488.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2025-52488.svg)


## CVE-2025-49493
 Akamai CloudTest before 60 2025.06.02 (12988) allows file inclusion via XML External Entity (XXE) injection.

- [https://github.com/SystemVll/CVE-2025-49493](https://github.com/SystemVll/CVE-2025-49493) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2025-49493.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2025-49493.svg)


## CVE-2025-48827
 vBulletin 5.0.0 through 5.7.5 and 6.0.0 through 6.0.3 allows unauthenticated users to invoke protected API controllers' methods when running on PHP 8.1 or later, as demonstrated by the /api.php?method=protectedMethod pattern, as exploited in the wild in May 2025.

- [https://github.com/SystemVll/CVE-2025-48827](https://github.com/SystemVll/CVE-2025-48827) :  ![starts](https://img.shields.io/github/stars/SystemVll/CVE-2025-48827.svg) ![forks](https://img.shields.io/github/forks/SystemVll/CVE-2025-48827.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/dbarquero/cve-2025-32463-lab](https://github.com/dbarquero/cve-2025-32463-lab) :  ![starts](https://img.shields.io/github/stars/dbarquero/cve-2025-32463-lab.svg) ![forks](https://img.shields.io/github/forks/dbarquero/cve-2025-32463-lab.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/mickhacking/Thank-u-Next](https://github.com/mickhacking/Thank-u-Next) :  ![starts](https://img.shields.io/github/stars/mickhacking/Thank-u-Next.svg) ![forks](https://img.shields.io/github/forks/mickhacking/Thank-u-Next.svg)


## CVE-2025-27415
 Nuxt is an open-source web development framework for Vue.js. Prior to 3.16.0, by sending a crafted HTTP request to a server behind an CDN, it is possible in some circumstances to poison the CDN cache and highly impacts the availability of a site. It is possible to craft a request, such as https://mysite.com/?/_payload.json which will be rendered as JSON. If the CDN in front of a Nuxt site ignores the query string when determining whether to cache a route, then this JSON response could be served to future visitors to the site. An attacker can perform this attack to a vulnerable site in order to make a site unavailable indefinitely. It is also possible in the case where the cache will be reset to make a small script to send a request each X seconds (=caching duration) so that the cache is permanently poisoned making the site completely unavailable. This vulnerability is fixed in 3.16.0.

- [https://github.com/jiseoung/CVE-2025-27415-PoC](https://github.com/jiseoung/CVE-2025-27415-PoC) :  ![starts](https://img.shields.io/github/stars/jiseoung/CVE-2025-27415-PoC.svg) ![forks](https://img.shields.io/github/forks/jiseoung/CVE-2025-27415-PoC.svg)


## CVE-2025-7620
 The cross-browser document creation component produced by Digitware System Integration Corporation has a Remote Code Execution vulnerability. If a user visits a malicious website while the component is active, remote attackers can cause the system to download and execute arbitrary programs.

- [https://github.com/Yuri08loveElaina/cve_2025_7620](https://github.com/Yuri08loveElaina/cve_2025_7620) :  ![starts](https://img.shields.io/github/stars/Yuri08loveElaina/cve_2025_7620.svg) ![forks](https://img.shields.io/github/forks/Yuri08loveElaina/cve_2025_7620.svg)


## CVE-2025-7606
 A vulnerability classified as critical has been found in code-projects AVL Rooms 1.0. This affects an unknown part of the file /city.php. The manipulation of the argument city leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/sunhuiHi666/CVE-2025-7606](https://github.com/sunhuiHi666/CVE-2025-7606) :  ![starts](https://img.shields.io/github/stars/sunhuiHi666/CVE-2025-7606.svg) ![forks](https://img.shields.io/github/forks/sunhuiHi666/CVE-2025-7606.svg)


## CVE-2025-7605
 A vulnerability was found in code-projects AVL Rooms 1.0. It has been rated as critical. Affected by this issue is some unknown functionality of the file /profile.php. The manipulation of the argument first_name leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/sunhuiHi666/CVE-2025-7605](https://github.com/sunhuiHi666/CVE-2025-7605) :  ![starts](https://img.shields.io/github/stars/sunhuiHi666/CVE-2025-7605.svg) ![forks](https://img.shields.io/github/forks/sunhuiHi666/CVE-2025-7605.svg)


## CVE-2025-5755
 A vulnerability was found in SourceCodester Open Source Clinic Management System 1.0. It has been classified as critical. Affected is an unknown function of the file /email_config.php. The manipulation of the argument email leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/cyberajju/cve-2025-5755](https://github.com/cyberajju/cve-2025-5755) :  ![starts](https://img.shields.io/github/stars/cyberajju/cve-2025-5755.svg) ![forks](https://img.shields.io/github/forks/cyberajju/cve-2025-5755.svg)


## CVE-2025-4413
 The Pixabay Images plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the pixabay_upload function in all versions up to, and including, 3.4. This makes it possible for authenticated attackers, with Author-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/mheranco/CVE-2025-44136](https://github.com/mheranco/CVE-2025-44136) :  ![starts](https://img.shields.io/github/stars/mheranco/CVE-2025-44136.svg) ![forks](https://img.shields.io/github/forks/mheranco/CVE-2025-44136.svg)
- [https://github.com/mheranco/CVE-2025-44137](https://github.com/mheranco/CVE-2025-44137) :  ![starts](https://img.shields.io/github/stars/mheranco/CVE-2025-44137.svg) ![forks](https://img.shields.io/github/forks/mheranco/CVE-2025-44137.svg)


## CVE-2025-2525
 The Streamit theme for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'st_Authentication_Controller::edit_profile' function in all versions up to, and including, 4.0.1. This makes it possible for authenticated attackers, with subscriber-level and above permissions, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/mtjanus106/CVE-2025-25257](https://github.com/mtjanus106/CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/mtjanus106/CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/mtjanus106/CVE-2025-25257.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/Armand2002/Exploit-CVE-2025-1974-Lab](https://github.com/Armand2002/Exploit-CVE-2025-1974-Lab) :  ![starts](https://img.shields.io/github/stars/Armand2002/Exploit-CVE-2025-1974-Lab.svg) ![forks](https://img.shields.io/github/forks/Armand2002/Exploit-CVE-2025-1974-Lab.svg)


## CVE-2025-0316
 The WP Directorybox Manager plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 2.5. This is due to incorrect authentication in the 'wp_dp_enquiry_agent_contact_form_submit_callback' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they have access to the username.

- [https://github.com/MrPayloadC/CVE-2025-0316-Exploit](https://github.com/MrPayloadC/CVE-2025-0316-Exploit) :  ![starts](https://img.shields.io/github/stars/MrPayloadC/CVE-2025-0316-Exploit.svg) ![forks](https://img.shields.io/github/forks/MrPayloadC/CVE-2025-0316-Exploit.svg)


## CVE-2023-5360
 The Royal Elementor Addons and Templates WordPress plugin before 1.3.79 does not properly validate uploaded files, which could allow unauthenticated users to upload arbitrary files, such as PHP and achieve RCE.

- [https://github.com/X3RX3SSec/CVE-2023-5360](https://github.com/X3RX3SSec/CVE-2023-5360) :  ![starts](https://img.shields.io/github/stars/X3RX3SSec/CVE-2023-5360.svg) ![forks](https://img.shields.io/github/forks/X3RX3SSec/CVE-2023-5360.svg)

