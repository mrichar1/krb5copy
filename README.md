# krb5copy

A simple tool to allow copying of kerberos credentials from one cache to another. Especially useful on systems where caches are generated automatically as `FILE` but would better suit a collection like `DIR` or `KEYRING`.

## Installation

There are 2 versions available - `C` and `Python`. The python version has more functionality, but the C version is more easily distributed.

### C

This tool relies on `krb5.h`, commonly provided by `libkrb5-dev` or `krb5-devel` packages on Debian and Redhat distributions.

`make`

### C Usage

Source cache: default ccache (`$KRB5CCNAME` variable, or system default).

Target cache: `$KRB5CCNEW` environment variable.

Improvements to add same argument functionality as Python welcome!


### Python

This tool relies on the python [krb5](https://pypi.org/project/krb5/) package.

`pip install -r requirements.txt`

### Python Usage

```
krb5copy.py --help
usage: krb5copy.py [-h] [-l LOG_LEVEL] [-c SOURCE_CACHE] [-n TARGET_CACHE] [-f]

Kerberos ticket cache moving utility

options:
  -h, --help            show this help message and exit
  -l LOG_LEVEL, --log_level LOG_LEVEL
                        Set log level: DEBUG, INFO, WARNING (default), ERROR, CRITICAL
  -c SOURCE_CACHE, --source_cache SOURCE_CACHE
                        Source cache. Defaults to value of $KRB5CCNAME or system default.
  -n TARGET_CACHE, --target-cache TARGET_CACHE
                        Target cache (e.g. DIR:/tmp/krb5cc_$(id -u)). Can also be set via environment variable: KRB5CCNEW.
  -f, --force           Force overwrite of existing credentials in new cache.
```

### Examples

```
# Copy the default cache ($KRB5CCNAME) into a KEYRING collection, and switch it to be the default
KRB5CCNEW="KEYRING:persistent:$(id -u)"
krb5copy
export KRB5CCNAME=$KRB5CCNEW
```

```
# Copy a specific cache into a DIR collection
KKRB5CCNAME=FILE:/tmp/krb5cc_1000 KRB5CCNEW=DIR:/tmp/krb5cc_dir krb5copy
```


