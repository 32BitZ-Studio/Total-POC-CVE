import sys 
from ctypes import * 

PAGE_READWRITE = 0x04 
PROCESS_ALL_ACCESS = (0x00F0000 | 0x0010000 | 0xFF)
VIRTUAL_MEM = (0x1000 | 0x2000)

#open kernel32
kernel32 = windll.kernel32 

#take the pid
pid = " "
dll_path = " "
#take length 
dll_len  = len(dll_path)

#open a process
h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

#check
if not h_process: 
    print("Error in PID")
    sys.exit(0)

#Create a virtual process 
arg_address = kernel32.VirtualAllocEx(
    h_process, 
    0,
    dll_len,
    VIRTUAL_MEM, 
    PAGE_READWRITE
)

written = c_int(0)

kernel32.WriteProcessMemory(h_process, arg_address, 
                            dll_path, 
                            dll_len,
                            byref(written))

h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")

h_loadlib = kernel32.GetProcAddress(h_kernel32, "LoadLibrartA")

thread_id = c_ulong(0)
#check
if not kernel32.CreateRemoteThread(h_process, None, 0, 
                                   h_loadlib, arg_address,
                                   0, byref(thread_id)):
    print("FAILED TO INJECT THE DLL")
    sys.exit(0)
print("Remote Thread created: " + thread_id.value)
    
