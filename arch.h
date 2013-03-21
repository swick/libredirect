#ifndef LIBREDIRECT_ARCH_H__
#define LIBREDIRECT_ARCH_H__

#if defined(__amd64__) || \
	defined(__i386__)
#else
#error unsupported architecture
#endif

#include <stdlib.h>

int init_jump_instruction(void *from, void *to, void **instruction, size_t *size);

int destroy_jump_instruction(void *instruction);

#endif
