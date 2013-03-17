#include <stdio.h>
#include <dlfcn.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <redirect.h>

#define UNUSED(X) (void)(X)


void (*func_a_replaced)(int some_arg);

void func_a(int some_arg) {
	printf("void func_a(int some_arg=%d)\n", some_arg);
}

void func_b(int some_arg) {
	printf("void func_b(int some_arg=%d)\n", some_arg);
}

int main(int argc, char **argv) {
	UNUSED(argc);
	UNUSED(argv);

	int err = 0;
	void *self = dlopen(NULL, RTLD_LAZY);
	void *func_a_addr = dlsym(self, "func_a");
	void *func_b_addr = dlsym(self, "func_b");

	assert(func_a_addr != NULL);
	assert(func_b_addr != NULL);

	func_a(42);

	libredirect_init();

	if((err = libredirect_redirect(func_a_addr, func_b_addr, func_a_replaced))) {
		printf("libredirect_redirect failed: %s (%d)\n", strerror(err), err);
		return err;
	}

	libredirect_destroy();

	func_a(42);

	return 0;
}
