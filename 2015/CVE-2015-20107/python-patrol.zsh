#!/usr/bin/env zsh
## python-patrol.zsh

# Scans for Python installations on macOS, and run CVE-2015-20107.py script from working directory to report whether
# patching is needed.
# Use sudo to search the entire macOS root filesystem as root user.

# Make sure to run this from an app with Full Disk Access permission - i.e. ensure iTerm.app has
# Full Disk Access enabled in Apple System Settings, Security & Privacy Privacy & Security.

# detect if script has full disk access permission and bail out if not
# thanks to Chris Dzombak for https://www.dzombak.com/blog/2021/11/macOS-Scripting-How-to-tell-if-the-Terminal-app-has-Full-Disk-Access.html
if ! plutil -lint /Library/Preferences/com.apple.TimeMachine.plist >/dev/null ; then
  echo "This script requires your terminal app to have Full Disk Access."
  echo "Add this terminal to the Full Disk Access list in System Preferences > Security & Privacy, quit the app, and re-run this script."
  exit 1
fi

# script must run as root
if [ "$( id -u )" -ne 0 ]; then
  echo "Please run this script as root or using sudo!"
  exit 1
fi


# BSD find invocation:
# Use -prune to avoid traversing and omit duplicate read-only mounted data volume + system volumes.
# filter to find files that match all of these criteria
#   named either python or python3,
#   executable bit set,
#   type file or symlink
# execute 'ls -l'  to show the details on the python interpreter executable or symlink
# execute the python interpreter found with the CVE-2015-20107.py script from current folder
# redirect stderr to omit errors, there will be a lot because of attempts to access macOS restricted folders
sudo find / \
  -path /System -prune -or \
  \( \
    \( -name python -or -name python3 \) \
    -perm +uog+x \
    \( -type f -o -type l \) \
  \) \
  -exec ls -l {} \; \
  -exec {} ./CVE-2015-20107.py \; \
   2>/dev/null
