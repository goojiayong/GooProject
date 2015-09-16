#include "check-license.h"

int _lic_log(const char* file, const char* function, int line, const void* msg ){
	FILE* fp = NULL;
	struct timeval   tv; 
	char timestr[TIMESTRSIZE] = {};
	int ret = 0;
	struct tm tm;

	system("mkdir -p /var/log/.gemfs/");
	fp = fopen(LOGFILE, "a");
	if( NULL == fp){
		fprintf(stderr, "open logfile error\n");
		return -1;
	}

	ret = gettimeofday (&tv, NULL);
	if(gmtime_r(&tv.tv_sec, &tm)){
		strftime(timestr, sizeof(timestr), TIMEFMT, &tm);
	}else {
		strncpy(timestr, "N/A", strlen(timestr));
	}

	ret = sprintf(timestr + strlen(timestr)," [ %s: %s(): %d: %s ]\n", file, function, line, msg);
	fwrite(timestr, strlen(timestr), 1, fp);
	fclose(fp);
	return 0;
}
/*******************************************************************************
 * * 函数名称  : syscmd_result
 * * 函数描述  : 执行shell命令，并返回执行结果。
 * * 输入参数  : char* cmd     : 要执行的shell命令
 * 		 char* getinfo ：用于保存执行shell命令的结果
 * * 输出参数  : char* getinfo ：shell命令的结果 
 * * 返回值    : 0:success  other:failed
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/09/03    郭家勇   新建
 * *******************************************************************************/
int syscmd_result(char* cmd, char* getinfo){
	pid_t pid;
	int ret = 0;
	int i = 0;
	int fd[2] = {0};
	FILE   *stream;
	FILE   *wstream;
	char buf[2048] = {};

	stream = popen( cmd, "r" );
	if(stream == NULL){
		lic_log("popen error");
		ret = -1;
		goto out;
	}
	fread(buf, 1, sizeof(buf), stream);
	pclose(stream);

	memset(getinfo, 0, sizeof(getinfo));
	memcpy(getinfo, buf, strlen(buf));

/*
	//创建管道
	ret = pipe(fd);
	if(ret == -1){
		perror("pipe");
		//_exit(1);
		lic_log("ERROR pipe failed");
		goto out;
	}

	//创建子进程，目的  1exec 2复制管道文件描述符
	pid = vfork();
	if(pid < 0){
		perror("vfork");
		lic_log("vfork error");
		ret = -1;
	}else if(pid == 0){
		dup2(fd[1], 1);//标准输出重定向到管道的写端

		execlp("/bin/bash","bash","-c", cmd, NULL);
	}
	else{
		char result[2048] = "";
		read(fd[0], result, sizeof(result));//从管道的读端读取数据
		*/
		/*
		for(i=0;i< strlen(result);i++){
	        	//result[i] = toupper(result[i]);
	        	//result[i] = tolower(result[i]);

		}
		if(strlen(result) != 0){
			memcpy(getinfo, result, strlen(result));
		}
	}
		*/



out:
	return ret;
}

/*******************************************************************************
 * * 函数名称  : get_devinfo
 * * 函数描述  : 获取设备指纹信息名称
 * * 输入参数  : char* dfp_info: 用于保存获取的设备指纹信息名称
 * * 输出参数  : 设备指纹信息名称
 * * 返回值    : 0:success  other:failed
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/09/03    郭家勇   新建
 * *******************************************************************************/
int get_devinfo(char* dfp_info){
	char mainboard[32] = {};
	char mac[256] = {};
	char cpunum[5] = {};
	int i = 0;
	int ret = 0;
	ret = syscmd_result(MAINBOARDSERIALCMD, (char*)mainboard);
	if(ret){
		lic_log("get mainboardserial failed");
		goto out;
	}
	ret = syscmd_result(NETWORKMACCMD, (char*)mac);
	if(ret){
		lic_log("get networkmac failed");
		goto out;
	}
	ret = syscmd_result(CPUNUMBERCMD, (char*)cpunum);
	if(ret){
		lic_log("get cpunum failed");
		goto out;
	}
	
	strncat(dfp_info, "<SSDFP><MainboardSerial>", 25);
	strncat(dfp_info, mainboard, strlen(mainboard));
	strncat(dfp_info, "/MainboardSerial>", 19);
	for(i=0;i<(strlen(mac)/18);i++){
		strncat(dfp_info, "<EthAddr>", 9);
		strncat(dfp_info, mac+(i*18), 18);
		strncat(dfp_info, "/EthAddr>", 10);
	}
	strncat(dfp_info, "<CPUNum>", 8);
	strncat(dfp_info, cpunum, strlen(cpunum));
	strncat(dfp_info, "/CPUNum></SSDFP>", 16);
	
	for(i=0;i<strlen(dfp_info);i++){
		if(dfp_info[i] == ':'){
			dfp_info[i] = '-';
		}
		else if(dfp_info[i] == '\n'){
			dfp_info[i] = '<';
		}
	}
out:
	return ret;
}

/* puid -- print a UUID */
void puid(uuid_t u)
{
        printf("%08x-%04x-%4.4x-%2.2x%2.2x-", u.time_low, u.time_mid,
			u.time_hi_and_version, u.clock_seq_hi_and_reserved,
			u.clock_seq_low);
	int i;
	for (i = 0; i < 6; i++)
		printf("%02x", u.node[i]);
	printf("\n");
}

/*******************************************************************************
 * * 函数名称  : create_dfp
 * * 函数描述  : 根据设备指纹信息名称生成DFP(设备指纹)
 * * 输入参数  : char* dfp_info: 保存了获取的设备指纹信息名称
 * 		 char* dfp     : 用于保存生成的DFP
 * * 输出参数  : char* dfp     : 生成的DFP
 * * 返回值    : 0:success  other:failed
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/09/04    郭家勇   新建
 * *******************************************************************************/
int create_dfp(char* dfp_info, char* dfp){
	int ret = 0;
	uuid_t u;
	uuid_t nsid = {/* 6ba7b810-9dad-11d1-80b4-00c04fd430c8 */
    		0x6ba7b810,
		0x9dad,
		0x11d1,
 		0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
	};
	/*
	byte* test = &nsid;
	int j;
	for(j=0; j<16; j++){
		printf("%02x", test[j]);
	}
	printf("\n");
	*/
	uuid_create_md5_from_name(&u, nsid, "www.widgets.com", 15);
	//puid(u);
        sprintf(dfp, "%08x-%04x-%4.4x-%2.2x%2.2x-", u.time_low, u.time_mid,
			u.time_hi_and_version, u.clock_seq_hi_and_reserved,
			u.clock_seq_low);
	int i;
	char tmp[10][2] = {};
	for (i = 0; i < 6; i++)
		sprintf(tmp[i], "%2.2x", u.node[i]);
	strcat(dfp, *tmp);
	if(strlen(dfp) != 36){
		ret = -1;
	}
	return ret;

}

/*******************************************************************************
 * * 函数名称  : copy_file
 * * 函数描述  : 拷贝文件
 * * 输入参数  : char* src_file  : 源文件
 *		 char* dest_file : 目标文件
 * * 输出参数  : char* dest_file : 目标文件
 * * 返回值    : 0:success  other:failed
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/09/04    郭家勇   新建
 * *******************************************************************************/
int copy_file(char* src_file, char* dest_file){
	int c;
	char ch;
	FILE *fpsrc, *fpdest;  //定义两个指向文件的指针

	fpsrc = fopen(src_file, "rb");    //以读取二进制的方式打开源文件
	if(fpsrc == NULL){
		fprintf(stderr, "no such license file\n");
		lic_log("no such license file");
		return -1;
	}
/*
	ch = fgetc(fpsrc);
	if(ch == EOF){
		fprintf(stderr, "the license file is empty");
		lic_log("the license file is empty");
		return -1;
	}
*/
	fpdest = fopen(dest_file, "wb");  //以写入二进制的方式打开目标文件
	if(fpdest == NULL){
		lic_log("open temporary license file failed");
		return -1;
	}
	while((c=fgetc(fpsrc))!=EOF){   //从源文件中读取数据知道结尾
		fputc(c, fpdest);
	}
	fclose(fpsrc);  //关闭文件指针，释放内存
	fclose(fpdest);
	return 0;
}


/*******************************************************************************
 * * 函数名称  : replace_dfp
 * * 函数描述  : 替换DFP。先换原始license 文件拷贝到临时license 文件，
 * 		 然后替换临时license 文件中的DFP。
 * * 输入参数  : char* dfp : DFP(设备指纹)
 * * 输出参数  : N/A
 * * 返回值    : 0:success  other:failed
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/09/04    郭家勇   新建
 * *******************************************************************************/
int replace_dfp(char* dfp){
	int ret = 0;
	char cmd[512] = {};
        ret = copy_file(LICENSEFILE, LICENSETMPFILE);	
	if(ret){
		lic_log("copy license file failed ");
		goto out;
	}

	sprintf(cmd, "sed -i 's/<DFP>.*<\\/DFP>/<DFP>%s<\\/DFP>/g' %s", 
			dfp, LICENSETMPFILE);

	//system(cmd);
out:
	return ret;
}

/*******************************************************************************
 * * 函数名称  : extract_license 
 * * 函数描述  : regular license.xml
 * * 输入参数  : argv[1]:the path to License.xml 
 * * 输出参数  : src_license which saved regular string for sign
 * * 返回值    : 0:success  other:failed
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/08/11    Zhang Shifang   新建
 * *******************************************************************************/
int extract_license(char* license_path, int type)
{
        char cmdline[50];
        char* path = "mylicense.sh";
        FILE *fp;

        fp = fopen(path, "w+");
        if(NULL == fp)
        {
		lic_log("open license failed");
                return -1;
        }

        //write a shell which used to regular license file
        if(0 == type)
        {
                fputs("#!/bin/bash\nlicense_path=$1\ntouch src_license\n", fp);
                fputs("cat ${license_path} |sed -rn '/Feature|Resource/{:1; N; /\\/Feature|\\/Resource/{s/^ +|\\n +//g;s/ /_/g;w src_license\n", fp);
                fputs(";b}; b1}'", fp);
        }
        else if(1 == type)
        {
                fputs("#!/bin/bash\nlicense_path=$1\ntouch src_license\n", fp);
                fputs("cat ${license_path} |sed -rn 's/^ +|\\n +//g;s/ /_/g;p'|tr -d '\
\n' > src_license", fp);
        }
        else
        {
		lic_log("Wrong type");
                return -1;
        }

        fclose(fp);

        //execute the shell
        system("chmod +x mylicense.sh");
        sprintf(cmdline, "./mylicense.sh %s", license_path);
        system(cmdline);

        //system("rm -rf mylicense.sh");

        return 0;
}

/*******************************************************************************
 * * 函数名称  : sha_strline
 * * 函数描述  : 计算"src_license" 文件中每行字符串的哈希值
 * * 输入参数  : unsigned char* sha_str: 用于保存哈希值
 * * 输出参数  : "src_license" 文件每行的哈希值
 * * 返回值    : 0:success  other:failed
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/09/07   郭家勇   新建
 * *******************************************************************************/
int sha_strline(unsigned char* sha_str){
	FILE* fp;
	char strline[4096];
	char* filename = "src_license";
	unsigned char* str_tmp = NULL;
	int ret = 0;

	//unsigned char str_tmp[2*SHA256_DIGEST_LENGTH] = {};
	//unsigned char str_tmp = (void*)calloc(1, 2*SHA256_DIGEST_LENGTH);
	fp = fopen(filename,"r");
	if(NULL == fp){
		lic_log("open src_license failed");
		ret = -1;
		goto out;
	}

	int i = 0;
	while(!feof(fp)){
		memset(strline, 0, sizeof(strline));				
		fscanf(fp, "%s", strline);

		if(!strlen(strline))
			continue;
		str_tmp = SHA256_encrypt(strline);
		strncat(sha_str, str_tmp, strlen(str_tmp));
	}
	fclose(fp);
	system("rm -rf src_license");

out:
	return ret;
}

/*******************************************************************************
 * * 函数名称  : sha_license_file
 * * 函数描述  : 计算整个临时license 文件的哈希值
 * * 输入参数  : unsigned char* sha_file : 用于保存整个临时license 文件的哈希值
 * 		 unsigned char* sha_feature : 用于保存license文件中feature的哈希
 * * 输出参数  : sha_file, sha_feature。
 * * 返回值    : 0:success  other:failed
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/09/07   郭家勇   新建
 * *******************************************************************************/
int sha_license_file(unsigned char* sha_file, unsigned char* sha_feature){
	int ret = 0;
	system(REPLACEFILESIGN);
	extract_license(LICENSETMPFILE, EXTRACT_ALL);

	ret = sha_strline(sha_file);
	if(ret){
		lic_log("hash temporary license file failed");
		goto out;
	}
		
	system(REPLACEFEATURESIGN);

	extract_license(LICENSETMPFILE, EXTRACT_PART);
	ret = sha_strline(sha_feature);
	if(ret){
		lic_log("hash tmp license feature failed");
		goto out;
	}
out:
	return ret;
}

/*******************************************************************************
 * * 函数名称  : decryption_rsa
 * * 函数描述  : 解密原始license 文件的哈希值和feature 的签名
 * * 输入参数  : unsigned char* srcfile_sha : 用于保存原始license 文件的哈希值
 * 		 unsigned char* srcfeature_sha: 用于保存原始license文件中feature的哈希
 * * 输出参数  : srcfile_sha, srcfeature_sha
 * * 返回值    : 0:success  other:failed
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/09/07   郭家勇   新建
 * *******************************************************************************/
int decryption_rsa(unsigned char* srcfile_sha, unsigned char* srcfeature_sha){
	int i = 0;
	int ret = 0;
	unsigned char file_sign[FILESINGLINE+1] = {};
	unsigned char feature_sign[FEATURESINGLINE*20] = {};
	char tmp_sign[FILESINGLINE+1] = {};
	unsigned char tmp_sha[2*SHA256_DIGEST_LENGTH+1] = {};

	ret = access(PUBKEYPATH, 0);
	if(ret){
		lic_log("the pubkey.pem does not exit");
		goto out;
	}

	ret = syscmd_result(GETFILESING , file_sign);
	if(ret || strlen(file_sign) == 0){
		lic_log("get license file sign failed");
		ret = -1;
		goto out;
	}
	ret = syscmd_result(GETFEATURESING, feature_sign);
	if(ret || strlen(feature_sign) == 0){
		lic_log("get license feature sign failed");
		ret = -1;
		goto out;
	}

	sprintf(srcfile_sha, "%s", dec_string(file_sign, PUBKEYPATH));

	for(i=0; i<(strlen(feature_sign)/FILESINGLINE); i++){
		memset(tmp_sign, 0, strlen(tmp_sign));
		memcpy(tmp_sign, feature_sign+(i*FILESINGLINE), FILESINGLINE);

		sprintf(tmp_sha, "%s",  dec_string(tmp_sign, PUBKEYPATH));
		memcpy((srcfeature_sha+(i*2*SHA256_DIGEST_LENGTH)), 
				tmp_sha, strlen(tmp_sha));
	}
out:
	return ret;
}

/*********************************************************************************
 * * 函数名称  : check_time
 * * 函数描述  : 检查license 文件是否到期
 * * 输入参数  : N/A
 * * 输出参数  : N/A
 * * 返回值    : 0:success  other:failed
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/09/09   郭家勇   新建
 * *******************************************************************************/
int check_time(){
	struct tm license_time;
	long  user_time;
	long  cur_time;
	long  cre_time;
	long  val_time;
	time_t create_time;
	time_t current_time;
	char valid_date[5] = {};
	char lic_time[25] = {};
	char fmt[] = "%Y-%m-%d-%H:%M:%S";
	int  ret = 0;

	ret = syscmd_result(LICENSECREATETIME, lic_time);
	if(ret){
		lic_log("get license create time failed");
		goto out;
	}
	strptime(lic_time, fmt, &license_time);
	create_time = mktime(&license_time);	

	time(&current_time);
	cur_time = current_time;
	cre_time = create_time;
	
	user_time = cur_time - cre_time;

	ret = syscmd_result(LICENSETERMVALIDITY, valid_date);
	if(ret){
		lic_log("get license valid date failed");
		goto out;
	}
	val_time = (atoi(valid_date)*24*60*60);
	if(val_time < user_time){
		//lic_log("License file has expired");
		ret = -1;
	}

out:
	return ret;

}

/*******************************************************************************
 * * 函数名称  : compare_license
 * * 函数描述  : 检查license 文件是否损坏，检查license文件是否到期 
 * * 输入参数  : char* tmpfile_sha : 临时license 文件的哈希值
 * 		 char* tmpfeature_sha : 临时license 文件中feature哈希值
 *		 char* srcfile_sha : 原始license 文件的哈希值
 * 		 char* srcfeature_sha: 原始license文件中feature的哈希
 * * 输出参数  : N/A
 * * 返回值    : 0:success  other:failed
 * * 备注      : N/A
 * * 修改日期     修改人   修改内容
 * * -----------------------------------------------
 * * 2015/09/07   郭家勇   新建
 * *******************************************************************************/
int compare_license(char* tmpfile_sha, char* tmpfeature_sha, 
		char* srcfile_sha, char* srcfeature_sha){
	int ret = 0;

	ret = strcmp(tmpfile_sha, srcfile_sha);
	if(ret != 0){
		fprintf (stderr,"license file error, please check that the license file correct\n");
		lic_log("license file damaged");
		goto out;
	} 

	ret = strcmp(tmpfeature_sha, srcfeature_sha);
	if(ret != 0 ){
		fprintf (stderr,"license file error, please check that the license file correct\n");
		lic_log("license file damaged");
		goto out;
	}

	ret = check_time();
	if(ret){
		fprintf(stderr, "license file has expired，please update license file\n");
		lic_log("license file has expired");
		goto out;
	}

out:
	return ret;

}

int check_license(){
	char dfp_info[512] = {};
	char dfp[37] = {};
	int ret = 0;
	
	unsigned char* tmpfile_sha = (void*)calloc(1, 2*SHA256_DIGEST_LENGTH);
	if(!tmpfile_sha){ 
		lic_log("Memory allocation failure");	
		goto out;
	}
	unsigned char* tmpfeature_sha = (void*)calloc(10, 2*SHA256_DIGEST_LENGTH);
	if(!tmpfeature_sha){ 
		lic_log("Memory allocation failure");	
		goto out;
	}
	unsigned char* srcfile_sha = (void*)calloc(1, 2*SHA256_DIGEST_LENGTH);
	if(!srcfile_sha){ 
		lic_log("Memory allocation failure");	
		goto out;
	}
	unsigned char* srcfeature_sha = (void*)calloc(10, 2*SHA256_DIGEST_LENGTH);
	if(!srcfeature_sha){ 
		lic_log("Memory allocation failure");	
		goto out;
	}

	ret = get_devinfo(dfp_info);
	if(ret){
		lic_log("get device info failed");
		goto out;
	}

	ret = create_dfp(dfp_info, dfp);
	if(ret){
		lic_log("create dfp error");
		goto out;
	}

	ret = replace_dfp(dfp);
	if(ret){
		lic_log("replace dfp failed");
		goto out;
	}
	
	ret = decryption_rsa(srcfile_sha, srcfeature_sha);
	if(ret){
		lic_log("decryption license sign failed");
		goto out;
	}

	ret = sha_license_file(tmpfile_sha, tmpfeature_sha);
	if(ret){
		lic_log("hash temporary license file failed");
		goto out;
	}

	ret = compare_license(tmpfile_sha, tmpfeature_sha, srcfile_sha, srcfeature_sha);
	if(ret){
		goto out;
	}

out:
#if 0
	printf("dfp_info=%s\n", dfp_info);
	printf("dfp=%s\n", dfp);
	printf("tmpfile_sha=%s\n", tmpfile_sha);
	printf("tmpfeature_sha=%s\n", tmpfeature_sha);
	printf("srcfile_sha=%s\n", srcfile_sha);
	printf("srcfeature_sha=%s\n", srcfeature_sha);
#endif

	if(ret)
		fprintf(stderr,"check license error, please check logfile \n");
	/*
	FREE(tmpfile_sha);
	FREE(tmpfeature_sha);
	FREE(srcfile_sha);
	FREE(srcfeature_sha);
	REMOVE(LICENSETMPFILE);
	*/
        return ret;	
}

