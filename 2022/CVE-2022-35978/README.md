

# CVE-2022-35978 POC
## Description

CVE-2022-35978 is a critical security vulnerability affecting Minetest versions up to and including 5.5.1. 

Minetest is a free, open-source voxel game engine that supports easy modding and game creation. In single-player mode, a mod can set a global setting that controls the Lua script loaded to display the main menu. This script is then loaded as soon as the game session is exited. The Lua environment in which the menu runs is not sandboxed, allowing it to directly interfere with the user's system.

To mitigate this issue, users are advised to update Minetest to version 5.6.0 or later, where the vulnerability has been addressed. 

The vulnerability has been assigned a CVSS v3.1 base score of 10.0 (Critical) by NVD, indicating a high potential impact. 

For more details, refer to the official Minetest changelog and the GitHub commit addressing this issue.

## Usage

![demo](./images/demo.gif)

To execute the script(s),

1) Place the directory '`cve_2022_35978`' in your '`[MINETEST_PATH]/mods`' directory.
2) Run the game binary '`[MINETEST_PATH]/bin/mintest.exe`' as Administrator.
3) Join a single player game.
4) Press the `Esc` key to return to the main menu.

## Notes

1) If you wish to see the lua and terminal output when the code is executing, you can update the Minetest configuration file (`minetest.conf`) to include the following line:

```
enable_console = true
```

From here, when you launch the game, it also launches the command terminal to output print messages.

2) This PoC was tested and verified to be working on Minetest version 5.0.0 on Windows 10 (Build 19045).

3) Testing PoC on Minetest version 5.6.0 confirms that this has been addressed:
```
2025-02-28 23:24:11: ERROR[Main]: ModError: Failed to load and run script from C:\Users\Can\Desktop\minetest-5.6.0-win64\bin\..\mods\cve_2022_35978\init.lua:
2025-02-28 23:24:11: ERROR[Main]: Attempted to set disallowed setting.
2025-02-28 23:24:11: ERROR[Main]: stack traceback:
2025-02-28 23:24:11: ERROR[Main]:       [C]: in function 'set'
2025-02-28 23:24:11: ERROR[Main]:       ...minetest-5.6.0-win64\bin\..\mods\cve_2022_35978\init.lua:29: in main chunk
2025-02-28 23:24:11: ERROR[Main]: Check debug.txt for details.
2025-02-28 23:24:11: ACTION[Main]: Server: Shutting down
```

## Motivations
I developed this Proof of Concept (PoC) solely for educational purposes and to facilitate learning about application security among my peers. Additionally, I was particularly interested in exploring this CVE due to my strong passion for both application security and video game programming.

## Disclaimer
This Proof of Concept (PoC) is provided strictly for educational purposes and to promote learning in the field of application security. I do not condone or support any malicious use of this code. Unauthorized exploitation of vulnerabilities may be illegal and unethical. Use this PoC responsibly and only in environments where you have explicit permission.

## References Used
- https://nvd.nist.gov/vuln/detail/CVE-2022-35978
- https://github.com/luanti-org/luanti/commit/da71e86633d0b27cd02d7aac9fdac625d141ca13
- https://github.com/luanti-org/luanti/issues/15584
- https://github.com/minetest-mods/mesecons/issues/388
- https://github.com/luanti-org/luanti/blob/master/minetest.conf.example#L2580-L2588
- https://thejeshgn.com/2018/10/01/howto-write-your-first-minetest-mod/
- https://minetest.org/assemble/git-trees/trolltest-newline/builtin/init.lua
- https://forum.luanti.org/viewtopic.php?t=25435
- https://forum.luanti.org/viewtopic.php?t=16044
- https://forum.luanti.org/viewtopic.php?t=24129
- https://forum.luanti.org/viewtopic.php?t=6659
