#include "check-license.h"

int main(){
	int ret = 0;
	ret = check_license();
	if(ret == 0){
		fprintf(stdout, "check license successful\n");
	}
	return 0;
}
