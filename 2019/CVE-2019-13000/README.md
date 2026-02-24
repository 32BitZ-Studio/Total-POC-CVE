# Detection tool for CVE 2019-13000

A tool that detect if your node has been victim of the invalid funding tx attack.

## Usage

```shell
java -jar checkfunding.jar --db eclair.sqlite
```

## Help

```shell
$ java -jar checkfunding.jar --help
checkfunding 1.0
Usage: checkfunding [options]

  --db <eclair.sqlite>  path to eclair.sqlite
  --conf <eclair.conf>  path to eclair.conf
  --help                prints this usage text

This utility will detect if your node has been victim of CVE-2019-13000.
Please see the thread on https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-August/002130.html for more details on the vulnerability.

NB: This tool will only work if you have been using released versions of Eclair. If you are on e.g. latest master, please contact support.

Example: checkfunding --db /path/to/eclair.sqlite --conf /path/to/eclair.conf

```
