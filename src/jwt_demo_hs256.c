/*
 * Quick demo of how to use libjwt using a HS256.
 *
 * @author gback, CS 3214, Spring 2018, updated Spring 2021
 * Added Jansson demo Fall'22
 *
 * I included the necessary free() operations here which
 * are needed in a long-running server.
 */
#include <jwt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <jansson.h>

static const char * NEVER_EMBED_A_SECRET_IN_CODE = "supa secret";

static void 
die(const char *msg, int error)
{
    fprintf(stderr, "%s: %s\n", msg, strerror(error));
    exit(EXIT_FAILURE);
}

int
main()
{
    jwt_t *mytoken;

    int rc = jwt_new(&mytoken);
    if (rc)
        die("jwt_new", rc);

    rc = jwt_add_grant(mytoken, "sub", "user0");
    if (rc)
        die("jwt_add_grant sub", rc);

    time_t now = time(NULL);
    rc = jwt_add_grant_int(mytoken, "iat", now);
    if (rc)
        die("jwt_add_grant iat", rc);

    rc = jwt_add_grant_int(mytoken, "exp", now + 3600 * 24);
    if (rc)
        die("jwt_add_grant exp", rc);

    rc = jwt_set_alg(mytoken, JWT_ALG_HS256, 
            (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, 
            strlen(NEVER_EMBED_A_SECRET_IN_CODE));
    if (rc)
        die("jwt_set_alg", rc);

    printf("dump:\n");
    rc = jwt_dump_fp(mytoken, stdout, 1);
    if (rc)
        die("jwt_dump_fp", rc);

    char *encoded = jwt_encode_str(mytoken);
    if (encoded == NULL)
        die("jwt_encode_str", ENOMEM);

    jwt_free(mytoken);
    printf("encoded as %s\nTry entering this at jwt.io\n", encoded);

    jwt_t *ymtoken;
    rc = jwt_decode(&ymtoken, encoded, 
            (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE, 
            strlen(NEVER_EMBED_A_SECRET_IN_CODE));
    if (rc)
        die("jwt_decode", rc);

    free(encoded);
    char *grants = jwt_get_grants_json(ymtoken, NULL); // NULL means all
    if (grants == NULL)
        die("jwt_get_grants_json", ENOMEM);

    jwt_free(ymtoken);
    printf("redecoded: %s\n", grants);
    
    // an example of how to use Jansson
    json_error_t error;
    json_t *jgrants = json_loadb(grants, strlen(grants), 0, &error);
    if (jgrants == NULL)
        die("json_loadb", EINVAL);

    free (grants);

    json_int_t exp, iat;
    const char *sub;
    rc = json_unpack(jgrants, "{s:I, s:I, s:s}", 
            "exp", &exp, "iat", &iat, "sub", &sub);
    if (rc == -1)
        die("json_unpack", EINVAL);

    printf ("exp: %lld\n", exp);
    printf ("iat: %lld\n", iat);
    printf ("sub: %s\n", sub);

    json_decref(jgrants);
}
