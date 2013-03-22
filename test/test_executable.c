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
	if(func_a_replaced)
		func_a_replaced(some_arg+1);
}

void log_func(const char *file, int line, int level, const char *str) {
	char *level_str = "";
	switch(level) {
		case libredirect_log_error:
			level_str = "error"; break;
		case libredirect_log_warning:
			level_str = "warning"; break;
		case libredirect_log_call:
			level_str = "call"; break;
		case libredirect_log_info:
			level_str = "info"; break;
	}
	printf("[%s at %s:%d] %s\n", level_str, file, line, str);
}

int main(int argc, char **argv) {
	UNUSED(argc);
	UNUSED(argv);

	int err = 0;
	void *self = dlopen(NULL, RTLD_LAZY);
	void *func_a_addr = dlsym(self, "func_a");
	void *func_b_addr = dlsym(self, "func_b");
	func_a_replaced = NULL;

	assert(func_a_addr != NULL);
	assert(func_b_addr != NULL);

	func_a(42);

	libredirect_set_log(log_func, libredirect_log_all);
	libredirect_init();

	if((err = libredirect_redirect(func_a_addr, func_b_addr, (void **)&func_a_replaced))) {
		printf("libredirect_redirect failed: %s (%d)\n", strerror(err), err);
		return err;
	}

	libredirect_destroy();

	func_a(42);

	return 0;
}
