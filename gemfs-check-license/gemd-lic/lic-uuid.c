#include "copyrt.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include "lic-uuid.h"

#ifndef ULONG64

#define ULONG64 unsigned long long 
#define ULONG unsigned long 

#endif
/* various forward declarations */
static void format_uuid_v3or5(lic_uuid_t *uuid, unsigned char hash[16],
    int v);

/* uuid_create_md5_from_name -- create a version 3 (MD5) UUID using a
 *    "name" from a "name space" */
void uuid_create_md5_from_name(lic_uuid_t *uuid, lic_uuid_t nsid, void *name,
                               int namelen)
{
    LIC_MD5_CTX c;
    unsigned char hash[16];
    lic_uuid_t net_nsid;
    /* put name space ID in network byte order so it hashes the same
 *        no matter what endian machine we're on */
    net_nsid = nsid;
  
    //net_nsid.time_low = htonl(net_nsid.time_low);
  
    //net_nsid.time_mid = htons(net_nsid.time_mid);
  
    //net_nsid.time_hi_and_version = htons(net_nsid.time_hi_and_version);

    MD5Init(&c);
    MD5Update(&c,(unsigned char*)&net_nsid, sizeof net_nsid);
    MD5Update(&c, name, namelen);
    MD5Final(hash, &c);
   
    /* the hash is in network byte order at this point */
    format_uuid_v3or5(uuid, hash, 3);
}

/* format_uuid_v3or5 -- make a UUID from a (pseudo)random 128-bit
 *    number */
void format_uuid_v3or5(lic_uuid_t *uuid, unsigned char hash[16], int v)
{
    /* convert UUID to local byte order */
    memcpy(uuid, hash, sizeof *uuid);
  
   // uuid->time_low = ntohl(uuid->time_low);
   // uuid->time_mid = ntohs(uuid->time_mid);
   // uuid->time_hi_and_version = ntohs(uuid->time_hi_and_version);
   //
    /* put in the variant and version bits */
    uuid->time_hi_and_version &= 0x0FFF;
    uuid->time_hi_and_version |= (v << 12);
    uuid->clock_seq_hi_and_reserved &= 0x3F;
    uuid->clock_seq_hi_and_reserved |= 0x80;
}


