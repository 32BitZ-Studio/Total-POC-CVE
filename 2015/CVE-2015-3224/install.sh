#!/bin/bash
# zc00l installation script for the modified metasploit ruby exploit script 
# cve-2015-3224 module does not accept arbitrary command execution.
# As the original exploit stands, it only accepts reverse shell or bind shell payloads.
# This modification enables the possibility of getting RCE without a shell.
# Written on 08/02/2018.



chk_error() {
    if [[ $? != 0 ]]; then
        echo "[!] Error: Something went wrong!";
        exit 1;
    fi
}

# Get the home directory of the user.
if [[ $HOME == "" ]]; then
    cd ~/;
    HOME=$(pwd);
fi

EXPLOIT_PATH="$HOME/.msf4/modules/exploits/multi/http/cve-2015-3224";

# Check for the folder existence.
if [[ ! -d $EXPLOIT_PATH ]]; then
    echo "[+] Creating exploit folder ...";
    mkdir -p $HOME/.msf4/modules/exploits/multi/http/cve-2015-3224
    chk_error;
fi

if [[ -f $EXPLOIT_PATH/ruby-on-rails-web-console2-rce.rb ]]; then
    echo "[+] Deleting older version ...";
    rm $EXPLOIT_PATH/ruby-on-rails-web-console2-rce.rb;
    chk_error
fi

echo "[+] Copying the exploit script over the metasploit framework folder ...";
cp *.rb $EXPLOIT_PATH
chk_error;

echo "[+] Exploit script was succesfully installed.";
