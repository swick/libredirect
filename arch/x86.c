#if defined(__amd64__) || defined(__i386__)

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
	if(instruction)
		*instruction = (void *)jmp;
	if(size)
		*size = sizeof(*jmp);

exit:
	return err;
}

int destroy_jump_instruction(void *instruction) {
	assert(instruction != NULL);
	free(instruction);
	return libredirect_error_none;
}

int is_jump_instruction(void *addr) {
	struct jmp_instruction *jmp = (struct jmp_instruction*) addr;
	return (jmp->opcode == 0xe9);
}

#endif
