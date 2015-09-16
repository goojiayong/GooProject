#ifndef __CHECK_LICENSE_H__
#define __CHECK_LICENSE_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include "lic-md5.h"
#include "lic-uuid.h"
#include "enc-dec.h"

#define MAINBOARDSERIALCMD "dmidecode -s baseboard-serial-number | tr 'A-Z' 'a-z' "
#define NETWORKMACCMD      "ip link | grep ether | awk '{print $2}'"
#define CPUNUMBERCMD       "cat /proc/cpuinfo |grep processor|wc -l"
#define GETFILESING        " grep Sign /usr/local/etc/gemfs/License-tmp.xml | sed 's#<Sign>##g;s#<\\/Sign>##g;s# ##g' | head -n 1"
#define GETFEATURESING     "grep \\<Sign\\>  /usr/local/etc/gemfs/License-tmp.xml | sed 's#<Sign>##g;s#<\\/Sign>##g;s# ##g' | sed '1d'"
#define REPLACEFILESIGN    "sed -i '0,/<Sign>/s/<Sign>.*/<Sign>*<\\/Sign>/' /usr/local/etc/gemfs/License-tmp.xml "
#define REPLACEFEATURESIGN  "sed -i 's/<Sign>.*/<Sign>*<\\/Sign>/' /usr/local/etc/gemfs/License-tmp.xml "  
#define LICENSECREATETIME   "grep AnnounceTime /usr/local/etc/gemfs/License.xml | sed 's#<AnnounceTime>##g;s#<\\/AnnounceTime>##g;s#^[[:space:]]*##g ;s# #-#g' "
#define LICENSETERMVALIDITY " grep  \\<Time\\> /usr/local/etc/gemfs/License.xml | sed 's#<Time>##g;s#<\\/Time>##g;s# ##g ' | head  -n 1 " 

#define PUBKEYPATH         "/usr/local/etc/gemfs/pubkey.pem" 
#define LICENSEFILE    "/usr/local/etc/gemfs/License.xml"
#define LICENSETMPFILE "/usr/local/etc/gemfs/License-tmp.xml"
#define LOGFILE        "/var/log/.gemfs/lic.log" 
#define TIMEFMT        "%Y-%m-%d %H:%M:%S"

#define EXTRACT_ALL  1
#define EXTRACT_PART 0
#define TIMESTRSIZE  512

#define SHALINE         64
#define FILESINGLINE    173
#define FEATURESINGLINE 173

#define lic_log(msg) do {                                \
	_lic_log(__FILE__, __FUNCTION__, __LINE__, msg); \
	}while(0)					 \

#define LICFREE(ptr)                               \
	if (ptr != NULL) {                      \
		free ((void *)ptr);             \
		ptr = (void *)0xeeeeeeee;       \
	}

#define REMOVE(file)                            \
	if(access(file, 0) == 0){               \
		remove(file);                   \
	}

int _lic_log(const char* , const char* , int , char*);
int syscmd_result(char* , char* );
int get_devinfo(char*);
void puid(lic_uuid_t );
int create_dfp(char*, char*);
int copy_file(char*, char*);
int replace_dfp(char*);
int extract_license(char*, int);
int sha_strline(unsigned char*);
int sha_license_file(unsigned char*, unsigned char*);
int decryption_rsa(unsigned char*, unsigned char*);
int check_time();
int compare_license(char*, char* ,char*, char*);
int check_license();

#endif
