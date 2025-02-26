# krb5copy

A simple tool to allow copying of kerberos credentials from one cache to another. Especially useful on systems where caches are generated automatically as `FILE` but would better suit a collection like `DIR` or `KEYRING`.

## Installation

This tool relies on the python [krb5](https://pypi.org/project/krb5/) package.

`pip install -r requirements.txt`

## Usage

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
# Copy the cache in the default keyring ($KRB5CCNAME) into a KEYRING collection
KRB5CCNEW="KEYRING:persistent:$(id -u)"
krb5copy
export KRB5CCNAME=$KRB5CCNEW
```

```
# Replace a DIR collection with a FILE cache
krb5copy -c FILE:/tmp/krb5cc_1000 -n DIR:/tmp/krb5cc_dir --force
```


