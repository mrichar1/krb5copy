#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <krb5.h>

// Global krb5 context
krb5_context context;
krb5_ccache src_ccache, tgt_ccache, write_ccache;
krb5_creds creds;
krb5_error_code ret;
krb5_cc_cursor cursor;
krb5_principal src_principal;
krb5_principal tgt_principal;

int cleanup(int retval) {
    if (creds.client != NULL) {
        krb5_free_cred_contents(context, &creds);
    }

    if (src_ccache != NULL) {
        krb5_cc_close(context, src_ccache);
    }

    if (tgt_ccache != NULL) {
        krb5_cc_close(context, tgt_ccache);
    }

    if (write_ccache != NULL) {
        krb5_cc_close(context, write_ccache);
    }

    if (context != NULL) {
        krb5_free_context(context);
    }

    exit(retval);
}

int log_krb5_error(const char *source, krb5_error_code ret) {
    if (ret) {
        fprintf(stderr, "%s: error: %s\n", source, krb5_get_error_message(context, ret));
        cleanup(1);
    }
    return 0;
}

int main() {

    // Initialize the Kerberos library
    log_krb5_error(
        "krb5_init_context",
        krb5_init_context(&context)
    );

    // Get current cache name (KRB5CCNAME or default)
    const char *src_cache_name = krb5_cc_default_name(context);
    fprintf(stderr, "Source cache: %s\n", src_cache_name);

    const char *tgt_cache_name = getenv("KRB5CCNEW");
    if (tgt_cache_name == NULL) {
        fprintf(stderr, "ERROR: KRB5CCNEW is undefined - target cache is required.\n");
        cleanup(1);
    }

    fprintf(stderr, "Target cache: %s\n", tgt_cache_name);

    // Try to open the source cache
    log_krb5_error(
        "krb5_cc_resolve:current",
        krb5_cc_resolve(context, src_cache_name, &src_ccache)
    );

    // Fail if src cache has no principals
    log_krb5_error(
        "ERROR: No principal found in source cache.",
        krb5_cc_get_principal(context, src_ccache, &src_principal)
    );

    // Open the target cache
    log_krb5_error(
        "krb5_cc_resolve:new",
        krb5_cc_resolve(context, tgt_cache_name, &tgt_ccache)
    );

    // Get target cache type
    const char *tgt_type = krb5_cc_get_type(context, tgt_ccache);

    // Check if target already has a principal in it
    krb5_cc_get_principal(context, tgt_ccache, &tgt_principal);
    krb5_data tgt_princ_data = {0};
    if (tgt_principal != NULL && tgt_principal->data != NULL) {
        tgt_princ_data = tgt_principal->data[0];
    }

    // Initialize cursor for sequence
    log_krb5_error(
        "krb5_cc_start_seq_get",
        krb5_cc_start_seq_get(context, src_ccache, &cursor)
    );

    // We will write to target cache by default
    write_ccache = tgt_ccache;

    // Protect existing principal
    if (tgt_princ_data.data != NULL) {
        fprintf(stderr, "Existing Target cache Principal: %s\n", tgt_princ_data.data);

        // FIXME: Add a way to force overwrites
        if (strcmp(tgt_type, "FILE") == 0) {
            fprintf(stderr, "Cache is of type FILE and contains a principal. Aborting.");
            cleanup(1);
        }

        // Target is a collection, so generate a new unique cache inside it.
        krb5_cc_set_default_name(context, tgt_cache_name);
        krb5_cc_new_unique(context, tgt_type, "", &write_ccache);
    }

    // Iterate over creds in src cache, writing to target
    while ((ret = krb5_cc_next_cred(context, src_ccache, &cursor, &creds)) == 0) {
        char *princ_name = NULL;
        krb5_unparse_name(context, creds.client, &princ_name);
        fprintf(stderr, "Copying credential: %s\n", princ_name);
        log_krb5_error(
            "krb5_cc_initialize",
            krb5_cc_initialize(context, write_ccache, creds.client)
        );
        log_krb5_error(
            "krb5_cc_store_cred",
            krb5_cc_store_cred(context, write_ccache, &creds)
        );
    }

    // Error if sequence ended unexpectedly
    if (ret != 0 && ret != KRB5_CC_END) {
        fprintf(stderr, "Error copying credentials: %s\n", krb5_get_error_message(context, ret));
    }

    // Success - tidy up.
    krb5_cc_end_seq_get(context, src_ccache, &cursor);
    cleanup(0);
}

