# MySQL server CVE-2016-6662 patch playbook

## How it works

It adds the [Percona fix](https://github.com/percona/percona-server/commit/c14be53e029442f576cced1fb8ff96b58e89f2e0#diff-144aa2f11374843c969d96b7b84247eaR261) to the mysqld_safe file.

## Which operating systems are supported

- CentOS
- FreeBSD

## How to use it

    ansible-playbook mysqld-safe-patch.yml
