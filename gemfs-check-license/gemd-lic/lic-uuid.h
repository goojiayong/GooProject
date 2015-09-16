#include "copyrt.h"
#include "global.h"
#include  "lic-md5.h"
//#include "sysdep.h"
//#include <openssl/md5.h>
#undef uuid_t
#define unsigned64_t unsigned long long
#define I64(C) C##LL
#define UUIDS_PER_TICK 1024

/* Set the following to a calls to get and release a global lock */
//#define LOCK
//#define UNLOCK

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
} lic_uuid_t;

/* uuid_create_md5_from_name -- create a version 3 (MD5) UUID using a
 *    "name" from a "name space" */
void uuid_create_md5_from_name(
    lic_uuid_t *uuid,         /* resulting UUID */
    lic_uuid_t nsid,          /* UUID of the namespace */
    void *name,           /* the name from which to generate a UUID */
    int namelen           /* the length of the name */
);


