#include <stdint.h>
#include <stddef.h>

#ifndef _RABBIT_CRYPTO_H
#define _RABBIT_CRYPTO_H
#endif

typedef struct rabbit_t {
	uint16_t		K[8];
	unsigned int 		X[8];		// State variables
	unsigned int 		C[8];		// Counter variables
	unsigned int 		G[8];		// G
	uint8_t 			Carry[8];	// Counter Carry bit
	uint8_t				Old_Carry[8];
	uint8_t 			tmp_carry;
	unsigned char 		S[16];
} rabbit_t;

void RABBIT_set_up_key_vars(rabbit_t *, unsigned char *);
int  RABBIT_init_variables(rabbit_t *);
void RABBIT_next_state_func(rabbit_t *);
void RABBIT_counter_carry_bit(rabbit_t *);
void RABBIT_counter_system(rabbit_t *);
void RABBIT_extraction_scheme(rabbit_t *);
void RABBIT_do_ecrypt(rabbit_t *, unsigned char *, size_t, unsigned char *);
int  RABBIT_key_stream(unsigned char *, rabbit_t *);
