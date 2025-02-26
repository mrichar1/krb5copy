import argparse
import logging
import os
import sys
import krb5

log = logging.getLogger()


class KrbMv:

    def __init__(self, args):
        self.args = args
        logging.basicConfig(format='%(levelname)s: %(message)s', level=getattr(logging, self.args.log_level))
        self.context = krb5.init_context()
        self.src_ccname = args.source_cache or krb5.cc_default_name(self.context)
        self.target_ccname = args.target_cache or os.getenv('KRB5CCNEW', '').encode('utf-8')
        if not self.target_ccname:
            log.error('One of --target_cache_name or KRB5CCNEW must be defined!')
            sys.exit(1)
        self.cur_cache = None
        self.target_cache = None
        self.main()

    def main(self):
        log.info("Source Cache: %s", self.src_ccname)
        log.info("Target Cache: %s", self.target_ccname)

        # Default assume target_cache has existing principal
        has_princ = True
        self.cur_cache = krb5.cc_resolve(self.context, self.src_ccname)
        self.target_cache = krb5.cc_resolve(self.context, self.target_ccname)
        try:
            krb5.cc_get_principal(self.context, self.target_cache)
        except krb5._exceptions.Krb5Error:
            # No principal found - cache is empty
            log.debug("No existing principal found.")
            has_princ = False

        write_cache = self.target_cache

        if has_princ and not self.args.force:
            # Protect existing principal
            if self.target_cache.cache_type == b'FILE':
                log.error("Cache is of type FILE and contains a principal, but '--force' is not set. Aborting.")
                sys.exit(1)

            # Target is a collection, so generate a new unique cache inside it...
            log.info("Principal found in existing cache - appending: %s: %s: %s", self.target_cache.name, self.target_cache.cache_type, self.target_cache.principal)
            krb5.cc_set_default_name(self.context, self.target_ccname)
            write_cache = krb5.cc_new_unique(self.context, self.target_cache.cache_type)
            log.debug("Generated new cache: %s, %s", write_cache.name, write_cache.cache_type)

        # Copy over credentials
        for cred in self.cur_cache:
            principal = cred.client
            krb5.cc_initialize(self.context, write_cache, principal)
            log.info('Copying credential: %s, %s, %s', cred.client, cred.server, cred.times)
            krb5.cc_store_cred(self.context, write_cache, cred)


def parse_args():
    parser = argparse.ArgumentParser(description="Kerberos ticket cache moving utility")
    parser.add_argument('-l', '--log_level', action="store", default="WARNING",
                        help="Set log level: DEBUG, INFO (default), WARNING, ERROR, CRITICAL")
    parser.add_argument('-c', '--source_cache', action="store", type=to_bytes,
                        help="Source cache. Defaults to value of $KRB5CCNAME or system default.")
    parser.add_argument('-n', '--target-cache', action="store", type=to_bytes,
                        help="""Target cache (e.g. DIR:/tmp/krb5cc_$(id -u)).
                             Can also be set via environment variable: KRB5CCNEW.""")
    parser.add_argument('-f', '--force', action="store_true",
                        help="Force overwrite of existing credentials in new cache.")

    return parser.parse_args()


def to_bytes(val):
    try:
        return val.encode('utf-8')
    except AttributeError:
        return val


if __name__ == '__main__':
    args = parse_args()
    KrbMv(args)
