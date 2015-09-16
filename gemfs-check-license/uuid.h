#include "copyrt.h"
#include "global.h"
#include "md5.h"
//#include "sysdep.h"
#undef uuid_t
#define unsigned64_t unsigned long long
#define I64(C) C##LL
#define UUIDS_PER_TICK 1024

/* Set the following to a calls to get and release a global lock */
#define LOCK
#define UNLOCK

typedef unsigned int   unsigned32;
typedef unsigned long   unsigned64;
typedef unsigned short  unsigned16;
typedef unsigned char   unsigned8;
typedef unsigned char   byte;

typedef unsigned64_t uuid_time_t;
typedef struct {
	    char nodeID[6];
} uuid_node_t;

typedef struct {
    unsigned32  time_low;
    unsigned16  time_mid;
    unsigned16  time_hi_and_version;
    unsigned8   clock_seq_hi_and_reserved;
    unsigned8   clock_seq_low;
    byte        node[6];
} uuid_t;

/* uuid_create -- generate a UUID */
int uuid_create(uuid_t * uuid);

/* uuid_create_md5_from_name -- create a version 3 (MD5) UUID using a
 *    "name" from a "name space" */
void uuid_create_md5_from_name(
    uuid_t *uuid,         /* resulting UUID */
    uuid_t nsid,          /* UUID of the namespace */
    void *name,           /* the name from which to generate a UUID */
    int namelen           /* the length of the name */
);

/* uuid_create_sha1_from_name -- create a version 5 (SHA-1) UUID
 *    using a "name" from a "name space" */
void uuid_create_sha1_from_name(

    uuid_t *uuid,         /* resulting UUID */
    uuid_t nsid,          /* UUID of the namespace */
    void *name,           /* the name from which to generate a UUID */
    int namelen           /* the length of the name */
);

/* uuid_compare --  Compare two UUID's "lexically" and return
 *         -1   u1 is lexically before u2
 *                  0   u1 is equal to u2
 *                           1   u1 is lexically after u2
 *                              Note that lexical ordering is not temporal ordering!
 *                              */
int uuid_compare(uuid_t *u1, uuid_t *u2);

