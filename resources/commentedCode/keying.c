#include <stdlib.h>
#include <stdio.h>
#include "utils.h"

int main(void) {
    check_for_correct_ip("172.16.101.30");
    printf("Found target IP address...\n");
    check_for_antivirus();
    printf("No antivirus found...\n");

    return EXIT_SUCCESS;
}