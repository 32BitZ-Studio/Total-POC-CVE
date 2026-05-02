## CVE-2026-3796
In QAX Virus Removal version dated 2025-10-22 and earlier, the affected driver `QKSecureIO_Imp.sys` rely on caller process's image to determine whether they are allowed to communicate to the mini filter driver. Attackers could 
impersonate a legitimate caller process image through tactics such as DLL sideloading, Process Injection to send message with specific payload to the mini filter and perform 
arbitrary process termination, such as protected process.

## Background
The application is used to remove virus. One of the imported function of the application's driver is `ZwTerminateProcess`, there is a lack of checking on the supplied process to kill, allowing arbitrary process termination. There is also a simple check by the driver on the caller process's identity, which can be bypassed using technique such as DLL sideloading.

## Usage
1) Complie the project in `x86`
2) Place the driver at `C:\Windows\system32\drivers`
3) In an Administrator command prompt, run `set pid=<your_target_pid_to_kill>`
4) Run the executable

Note: The vulnerable driver will not be shared in this project.

## Sample Output
<img width="1045" height="447" alt="image" src="https://github.com/user-attachments/assets/d3ef3963-f328-498d-bdc1-9110ca069e68" />


## Disclaimer
This tool is for educational and research purposes only. Use it only on systems you own or have explicit permission to test. The author is not responsible for any misuse or damage caused by this program.

## Buy Me a Coffee
<a href="https://www.buymeacoffee.com/cwjchoi" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>
