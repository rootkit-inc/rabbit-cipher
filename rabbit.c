/* The Rabbit Cipher Implementaion
The input must be 512 bits 

The algorithm:
First 256 bits 		X / State variables [8] x[0..7][32bits]
Last 256 bits 		C / Counter variables [8] c[0..7][32bits]

Each X has a correspondoing C variable

There is also -0-[0..7][i] - Counter carry bit


[The KEY] Must be 128 bits
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "./rabbit.h"
#include "./hexdump.h"


// 0xdeadc0de - 0xde[3] ad[2] c0[1] de[0] 
#define VAR_TO_UCHAR(integer_addr, i) (*(((unsigned char*)integer_addr) + i))

#define UCHAR_INTO_VAR(integer_addr, i, ch) (*((unsigned char*)(integer_addr)+i) = (unsigned char)ch)

#define ROTATE_R(x, SIZE, bits) ((x >> bits)|(x << (SIZE - bits)))

#define ROTATE_L(x, SIZE, bits) ((x << bits)|(x >> (SIZE - bits)))

#define GET_U16_FROM_VAR(addr, first, last) (((uint16_t)VAR_TO_UCHAR(addr, last) << 8) | VAR_TO_UCHAR(addr, first))
#define MOD_VAL 0x100000000		// 2 ** 32

static const int A_const[8] = {	0x4D34D34D, 0xD34D34D3,
								0x34D34D34, 0x4D34D34D,
								0xD34D34D3, 0x34D34D34,
								0x4D34D34D, 0xD34D34D3
							};

void RABBIT_set_up_key_vars(rabbit_t *cr, unsigned char *key) {
	int pos = 0;

	for (int i = 0; i < 8; i++, pos+=2) {
		for (int j = 0; j < 2; j++) {
			UCHAR_INTO_VAR(&cr->K[i], j, (unsigned char)key[pos+j]);
		}
	}
}

int RABBIT_init_variables(rabbit_t *cr) {
	unsigned char X_ch, C_ch;
	for (int i = 0; i < 8; i++)
		if (cr->K[i] == '\x00')
			return -1;

	/* Initialising the State X and Counter C variables */
	for (int j = 0; j < 8; j++) {
		if (j % 2 == 0) {		// For Even
			X_ch = cr->K[(j+1) % 8] | cr->K[j];
			C_ch = cr->K[(j+4) % 8] | cr->K[(j+5) % 8];
		} else {				// For Odd
			X_ch = cr->K[(j+5) % 8] | cr->K[(j+4) % 8];
			C_ch = cr->K[j] | cr->K[(j+1) % 8];
		}
	
		UCHAR_INTO_VAR(&cr->X[j], 0, (unsigned char)X_ch);
		UCHAR_INTO_VAR(&cr->C[j], 0, (unsigned char)C_ch);
	}
	return 0;
}

void RABBIT_next_state_func(rabbit_t *cr) {
	RABBIT_counter_system(cr);

	for (int j = 0; j < 8; j++) {
		int tmp_G = (cr->X[j] + cr->C[j]) % MOD_VAL;
		tmp_G *= tmp_G+1;

		cr->G[j] = (unsigned int)((((size_t)tmp_G) ^ ((size_t)tmp_G >> 32))% MOD_VAL);
		// printf("[%i]%lx\n", j, cr->G[j]);
	}


	cr->X[0] = cr->G[0] + ROTATE_L(cr->G[7], 32, 16) + ROTATE_L(cr->G[6], 32, 16);
	cr->X[1] = cr->G[1] + ROTATE_L(cr->G[0], 32, 8) + cr->G[7];
	cr->X[2] = cr->G[2] + ROTATE_L(cr->G[1], 32, 16) + ROTATE_L(cr->G[1], 32, 16);
	cr->X[3] = cr->G[3] + ROTATE_L(cr->G[2], 32, 8) + cr->G[2];
	cr->X[4] = cr->G[4] + ROTATE_L(cr->G[3], 32, 16) + ROTATE_L(cr->G[3], 32, 16);
	cr->X[5] = cr->G[5] + ROTATE_L(cr->G[4], 32, 8) + cr->G[4];
	cr->X[6] = cr->G[6] + ROTATE_L(cr->G[5], 32, 16) + ROTATE_L(cr->G[5], 32, 16);
	cr->X[7] = cr->G[7] + ROTATE_L(cr->G[6], 32, 8) + cr->G[6];
}

void RABBIT_counter_carry_bit(rabbit_t * cr) {
	// puts("[+++] NEW ROUND [+++]");
	uint8_t tmp;
	for (int j = 0; j < 8; j++)
		cr->Old_Carry[j] = cr->Carry[j];

	cr->Carry[0] = ((cr->C[0] + A_const[0] + cr->tmp_carry) >= MOD_VAL);
	// Start with the 0
	for (int j = 1; j < 8; j++) {
		tmp = ((cr->C[j] % MOD_VAL) + (A_const[j] % MOD_VAL) + (cr->Carry[j-1] << 1) >= MOD_VAL);
		if (tmp) {
			cr->Carry[j] = 1;
		} else {
			cr->Carry[j] = 0;
		}
		// printf("[=] CCbit %x\n", cr->Carry[j]);
	}

	cr->tmp_carry = (cr->Old_Carry[7] > cr->Carry[7]);
}

void RABBIT_counter_system(rabbit_t * cr) {
	RABBIT_counter_carry_bit(cr);
	for (int j = 0; j < 8; j++) {
		cr->C[j] = (cr->C[j]+A_const[j] + cr->Carry[j+1]) % MOD_VAL;
	}
}

void RABBIT_extraction_scheme(rabbit_t * cr) {
	for (int j = 0; j < 16; j+=2) {
	uint16_t tmp;
		// uint16_t a = GET_U16_FROM_VAR(&cr->X[j], 2, 3);
		// printf("X[%i] %x -- a %x\n", j, cr->X[j], a);
	
		if (j % 4 == 0) {
			tmp = GET_U16_FROM_VAR(&cr->X[j], 0, 1) ^ GET_U16_FROM_VAR(&cr->X[(j+5)%8], 2, 3);
		} else {
			tmp = GET_U16_FROM_VAR(&cr->X[j], 2, 3) ^ GET_U16_FROM_VAR(&cr->X[(j+3)%8], 0, 1);
		}
		cr->S[j] = VAR_TO_UCHAR(&tmp, 0);
		cr->S[j+1] = VAR_TO_UCHAR(&tmp, 1);
	}
}

void RABBIT_do_ecrypt(rabbit_t *cr, unsigned char *msg, size_t size, unsigned char *out) {
	for (int i = 0; i < size; i++) {
		out[i] = msg[i] ^ cr->S[i%16];
	}
}

// Linker scripts for parasite

int RABBIT_key_stream(unsigned char *key, rabbit_t * cr) {
	for (int i = 0; i < 16; i++) {
		if (key[i] == '\x00') {
			return -1;
		}
	}

	RABBIT_set_up_key_vars(cr, key);
	int err = RABBIT_init_variables(cr);
	if (err != 0)
		return -1;		// NEW_ERROR


	for (int i = 0; i < 4; i++)
		RABBIT_next_state_func(cr);

	for (int j = 0; j < 8; j++) {		// Inverse the counter system
		cr->C[(j+1)%8] = cr->C[(j+1)%8] ^ cr->X[(j+4+1)%8];
	}
	RABBIT_extraction_scheme(cr);

	return 0;
}

int main() {
	rabbit_t *cr = (rabbit_t*) malloc(sizeof(rabbit_t));
	memset(cr, 0, sizeof(rabbit_t));
	int err = RABBIT_key_stream("1234567890098765", cr);
	if (err == -1) {
		return err;
	}

	unsigned char *out = (unsigned char *)malloc(64*sizeof(unsigned char));
	unsigned char *plain_text = "HELLOHELLOHELLOHELLOHELLOHELLOHELLOHELLOHELLOHELLOHELLOHELLODONE";

	printf("===============>>>[ PLAIN TEXT ]===========>\n");
	hexdump(plain_text, 64);

	printf("===============>>>[ ENCRYPTED ]===========>\n");
	RABBIT_do_ecrypt(cr, plain_text, 64, out);
	hexdump(out, 64);

	printf("===============>>>[ DECRYPTED ]===========>\n");
	RABBIT_do_ecrypt(cr, out, 64, out);
	hexdump(out, 64);


	free(out);
	free(cr);
	return 0;
}