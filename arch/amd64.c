#ifdef __amd64__

#include <stdio.h>
#include <assert.h>
#include "../arch.h"
#include "../redirect.h"

struct jmp_instruction {
	unsigned char opcode;
	signed int address;
} __attribute__((__packed__));

int init_jump_instruction(void *from, void *to, void **instruction, size_t *size) {
	int err = libredirect_error_none;

	struct jmp_instruction *jmp = malloc(sizeof(*jmp));
	if(!jmp && (err = libredirect_error_nomem))
		goto exit;

	signed int rela = (signed int)(to - from);
	rela -= sizeof(*jmp);

	jmp->opcode = 0xe9;
	jmp->address = rela;
	*instruction = (void *)jmp;
	*size = sizeof(*jmp);

exit:
	return err;
}

int destroy_jump_instruction(void *instruction) {
	assert(instruction != NULL);
	free(instruction);
	return libredirect_error_none;
}

#endif
