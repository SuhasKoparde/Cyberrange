# Password Cracking Challenge Files

## Challenge Setup Files

### hashes.txt
```
# MD5 Hashes
5d41402abc4b2a76b9719d911017c592
098f6bcd4621d373cade4e832627b4f6
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

# SHA1 Hashes  
356a192b7913b04c54574d18c28d46e6395428ab
da39a3ee5e6b4b0d3255bfef95601890afd80709
77de68daecd823babbb58edb1c8e14d7106e83bb

# bcrypt Hashes
$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6ukj8C4.LG
$2b$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q

# NTLM Hashes
31d6cfe0d16ae931b73c59d7e0c089c0
8846f7eaee8fb117ad06bdd830b7586c
```

### users.txt
```
admin
user
guest
test
demo
root
administrator
manager
```

### wordlists/common_passwords.txt
```
password
123456
password123
admin
letmein
welcome
qwerty
abc123
Password1
admin123
root
toor
kali
password1
123456789
welcome123
```

### john_rules.conf
```
# Custom John the Ripper rules
[List.Rules:Custom]
# Append numbers
$[0-9]
$[0-9]$[0-9]

# Prepend and append
^[0-9]
$[0-9]

# Capitalize first letter
c

# All uppercase
u

# Reverse
r

# Leet speak
so0si1se3sa@
```

## Commands Reference

### Basic Hash Cracking
```bash
# Identify hash format
john --list=formats | grep -i md5

# Dictionary attack
john --wordlist=wordlists/common_passwords.txt hashes.txt

# Show cracked passwords
john --show hashes.txt

# Specific format
john --format=Raw-MD5 --wordlist=wordlists/common_passwords.txt hashes.txt
```

### Advanced Techniques
```bash
# Brute force attack
john --incremental hashes.txt

# Rule-based attack
john --wordlist=wordlists/common_passwords.txt --rules=Custom hashes.txt

# Combine wordlists
john --wordlist=wordlists/rockyou.txt --wordlist=wordlists/common_passwords.txt hashes.txt

# Session management
john --session=mysession hashes.txt
john --restore=mysession
```

### Hash Generation (for testing)
```bash
# Generate MD5
echo -n "password" | md5sum

# Generate SHA1
echo -n "password" | sha1sum

# Generate bcrypt
htpasswd -bnBC 12 "" password | tr -d ':\n'
```
