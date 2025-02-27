#include <stdio.h>
#include <stdlib.h>
#include <krb5.h>

// Global krb5 context
krb5_context context;
krb5_ccache src_ccache, tgt_ccache, write_ccache;
krb5_creds creds;
krb5_error_code ret;
krb5_cc_cursor cursor;
krb5_principal principal;

int cleanup(int retval) {
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

    char *parsed_principal = NULL;

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
        fprintf(stderr, "KRB5CCNEW is not set in the environment.\n");
        return 1;
    }

    // Try to open the source cache
    log_krb5_error(
        "krb5_cc_resolve:current",
        krb5_cc_resolve(context, src_cache_name, &src_ccache)
    );

    // Fail if src cache has no principals
    log_krb5_error(
        "ERROR: No principal found in source cache.",
        krb5_cc_get_principal(context, src_ccache, &principal)
    );

    // Open the target cache
    log_krb5_error(
        "krb5_cc_resolve:new",
        krb5_cc_resolve(context, tgt_cache_name, &tgt_ccache)
    );

    // Get target cache type
    const char *tgt_type = krb5_cc_get_type(context, tgt_ccache);
    fprintf(stderr, "Target cache type: %s\n", tgt_type);

    // Check if target already has a principal in it
    krb5_cc_get_principal(context, tgt_ccache, &principal);
    krb5_data princ_data = principal->data[0];

    // Initialize cursor for sequence
    log_krb5_error(
        "krb5_cc_start_seq_get",
        krb5_cc_start_seq_get(context, src_ccache, &cursor)
    );

    // We will write to target cache by default
    write_ccache = tgt_ccache;

    // Protect existing principal
    if (princ_data.data != NULL) {
        fprintf(stderr, "Existing Target cache Principal: %s\n", princ_data.data);

        if (tgt_type == "FILE") {
            fprintf(stderr, "Cache is of type FILE and contains a principal. Aborting.");
            cleanup(1);
        }


        // Target is a collection, so generate a new unique cache inside it...
        krb5_cc_set_default_name(context, tgt_cache_name);
        krb5_cc_new_unique(context, tgt_type, "", &write_ccache);

    }

    // Iterate over creds in src cache,
    while (krb5_cc_next_cred(context, src_ccache, &cursor, &creds) == 0) {
        krb5_principal princ = creds.client;
        // fIXME: handle errors from these with ret/log
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

