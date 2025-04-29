#ifndef ATTACKS_H
#define ATTACKS_H

void bind_shell(void);

void rev_shell(char *rev_ip, uint16_t rev_port, unsigned int seconds);

#endif