#!/bin/bash

# overwrite disk with random ciphertext or just zeroes. your disk, your choice.
#
# after reading a bit, i found a very good wiki post here:
# https://wiki.archlinux.org/title/Securely_wipe_disk/Tips_and_tricks
# the safe wipe method they suggested:
#
# PASS=$(tr -cd '[:alnum:]' < /dev/urandom | head -c128)
# openssl enc -aes-256-ctr -pass pass:"$PASS" -nosalt </dev/zero | dd obs=64K ibs=4K of=$DEVICE oflag=direct status=progress
#
# i had to add the -pbkdf2 option because you will get a "deprecated key derivation used" warning otherwise
# if you want to know what that means: https://www.comparitech.com/blog/information-security/key-derivation-function-kdf/
#
# using the suggested random data method is much slower but still very fast compared to the commercial safe erase tools or
# the other methods recommended by security professionals. for non-sensitive data and/or private use, writing zeroes is safe enough.
# oh and you may speed things up a bit by providing an "-iter" parameter to the function with a lower value than the default 10000. ;)
#
# if the device you want to wipe is a ssd, have a look at the secure erase feature: https://www.datadestroyers.eu/technology/secure_erase.html
# to secure erase a ssd:
# - install hdparm
# - check if device locked using hdparm -I /dev/sdX
# - set password: hdparm --user-master u --security-set-pass abc123 /dev/sdX
# - erase ssd: hdparm --user-master u --security-erase abc123 /dev/sdX
# of course you should replace the sdX with the device you're using. replacing the password is not necessary: it's only valid for that one erase session.
# good article on ssd forensics: https://blog.elcomsoft.com/2019/01/life-after-trim-using-factory-access-mode-for-imaging-ssd-drives/
#
# dj0Nz jul 25


if [[ $1 = "" ]]; then
    echo "Input?"
    exit 1
else
    TARGET=$1
fi

IS_MOUNT=$(sudo findmnt $TARGET)
if [[ ! $IS_MOUNT = "" ]]; then
    echo "$TARGET has mounted partitions!"
    exit 1
fi

IN_SCREEN=$(echo $TERM)
if [[ ! $IN_SCREEN = "screen" ]]; then
    echo "This script will run for a very long time. Consider using a screen session!"
fi

read -n 1 -p "Safe or quick erase? Enter [SsQq], any other key exits. " SORQ
case $SORQ in
    [Ss]* ) SAFE="Yes";;
    [Qq]* ) SAFE="No";;
    * ) echo ""; exit;;
esac

echo ""

if [[ $SAFE = "Yes" ]]; then
    PASS=$(tr -cd '[:alnum:]' < /dev/urandom | head -c128)
    echo "Overwriting $TARGET with random data..."
    openssl enc -aes-256-ctr -pbkdf2 -pass pass:"$PASS" -nosalt </dev/zero | sudo dd obs=64K ibs=4K of=$TARGET oflag=direct status=progress
else
    echo "Wiping $TARGET..."
    sudo dd if=/dev/zero of=/dev/sda bs=4096 status=progress
fi
