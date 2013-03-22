#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dis-asm.h>
#include <dlfcn.h>
#include <stdarg.h>

#include "redirect.h"
#include "arch.h"

#define UNUSED(X) (void)(X)
#define __PUBLIC __attribute__((visibility("default")))
#define MAX_ASM_INST_LENGTH 32 /* wild guess, have no clue */
#define MAX_MAPS_LINE_LENGTH 4096
#define LOG(...) libredirect_log(__FILE__, __LINE__, __VA_ARGS__)

enum status {
	status_none = 0,
	status_init = (1 << 0)
};

struct {
	enum status status;
	char *executable_path;
	bfd *abfd;
	disassemble_info *dis_info;
	disassembler_ftype disassemble;
	void (*log_func)(const char *, int, int, const char *);
	int log_level;
} libredirect = {0};

struct jmp_instruction {
	unsigned char jmp;
	void *address; 
} __attribute__((__packed__));

enum permission {
	permission_read = 1,
	permission_write = (1 << 1),
	permission_execute = (1 << 2)
};

struct segment {
	struct segment *next;
	void *start;
	void *end;
	enum permission permission;
	char *path;
};

char *libredirect_strerror(int errnum);
int destroy_segments(struct segment *segment);

void libredirect_log(const char *file, int line, int level, const char *format, ...) {
	if(!libredirect.log_func || !(level & libredirect.log_level))
		return;

	va_list list;

	va_start(list, format);
	size_t needed = vsnprintf(NULL, 0, format, list);
	va_end(list);

	char *str = NULL;
	char *buffer = malloc(needed+2);
	if(!buffer) {
		str = libredirect_strerror(libredirect_error_nomem);
	}
	else {
		va_start(list, format);
		vsnprintf(buffer, needed+1, format, list);
		va_end(list);
		str = buffer;
	}

	libredirect.log_func(file, line, level, str);

	if(buffer)
		free(buffer);
}

int null_fprintf(void *f, const char *str, ...) {
	UNUSED(f);
	UNUSED(str);
	return 0;
}

int read_memory(const struct segment *segment, const void *at, const size_t length, void *buf) {
	LOG(libredirect_log_call, __FUNCTION__);
	int err = libredirect_error_none;
	assert(segment != NULL);

	while(segment) {
		if(at < segment->end && at >= segment->start)
			break;
		segment = segment->next;
	}
	if(!segment && (err = libredirect_error_segments)) {
		LOG(libredirect_log_error, "no segment found at %p", at);
		goto exit;
	}

	if(segment->permission & permission_read) {
		goto read;
	}

	int permission =
		(segment->permission & permission_read) ? PROT_READ : 0 |
		(segment->permission & permission_write) ? PROT_WRITE : 0 |
		(segment->permission & permission_execute) ? PROT_EXEC : 0;

	int n_perm = permission | PROT_READ;

	LOG(libredirect_log_info, "set read permission on segment (%p-%p)", segment->start, segment->end);
	if(mprotect(segment->start, segment->end - segment->start, n_perm) < 0) {
		LOG(libredirect_log_error, "mprotect %d bytes at %p with permission %d failed: %s (%d)",
			segment->end - segment->start, segment->start, n_perm, strerror(errno), errno);
		err = libredirect_error_syscall;
		goto exit;
	}

read:
	LOG(libredirect_log_info, "read %d bytes of memory from %p", length, at);
	memcpy(buf, at, length);

	if(!(segment->permission & permission_read)) {
		LOG(libredirect_log_info, "restore permission on segment (%p-%p)", segment->start, segment->end);
		if(mprotect(segment->start, segment->end - segment->start, permission) < 0) {
			LOG(libredirect_log_error, "mprotect %d bytes at %p with permission %d failed: %s (%d)",
				segment->end - segment->start, segment->start, permission, strerror(errno), errno);
			err = libredirect_error_syscall;
			goto exit;
		}
	}

exit:
	return err;
}

int write_memory(const struct segment *segment, void *at, const size_t length, const void *buf) {
	LOG(libredirect_log_call, __FUNCTION__);
	int err = libredirect_error_none;
	assert(segment != NULL);

	while(segment) {
		if(at < segment->end && at >= segment->start)
			break;
		segment = segment->next;
	}
	if(!segment && (err = libredirect_error_segments)) {
		LOG(libredirect_log_error, "no segment found at %p", at);
		goto exit;
	}

	if(segment->permission & permission_write)
		goto write;

	int permission =
		((segment->permission & permission_read) ? PROT_READ : 0) |
		((segment->permission & permission_write) ? PROT_WRITE : 0) |
		((segment->permission & permission_execute) ? PROT_EXEC : 0);

	int n_perm = permission | PROT_WRITE;

	LOG(libredirect_log_info, "set write permission on segment (%p-%p)", segment->start, segment->end);
	if(mprotect(segment->start, segment->end - segment->start, n_perm) < 0) {
		LOG(libredirect_log_error, "mprotect %d bytes at %p with permission %d failed: %s (%d)",
			segment->end - segment->start, segment->start, n_perm, strerror(errno), errno);
		err = libredirect_error_syscall;
		goto exit;
	}

write:
	LOG(libredirect_log_info, "write %d bytes to memory at %p", length, at);
	memcpy(at, buf, length);

	/*  restore permission */
	if(!(segment->permission & permission_write)) {
		LOG(libredirect_log_info, "restore permission on segment (%p-%p)", segment->start, segment->end);
		if(mprotect(segment->start, segment->end - segment->start, permission) < 0) {
			LOG(libredirect_log_error, "mprotect %d bytes at %p with permission %d failed: %s (%d)",
				segment->end - segment->start, segment->start, permission, strerror(errno), errno);
			err = libredirect_error_syscall;
			goto exit;
		}
	}

exit:
	return err;
}

int init_segments(struct segment **seg) {
	LOG(libredirect_log_call, __FUNCTION__);
	int err = libredirect_error_none;
	FILE *maps = NULL;

	char map_path[PATH_MAX + 1];
	snprintf(map_path, PATH_MAX, "/proc/%d/maps", getpid());
	LOG(libredirect_log_info, "proccess maps are at %s", map_path);

	maps = fopen(map_path, "r");
	if(!maps && (err = libredirect_error_syscall)) {
		LOG(libredirect_log_error, "fopen failed: %s (%d)", strerror(errno), errno);
		goto exit;
	}

	char line[MAX_MAPS_LINE_LENGTH];
	struct segment *segments = NULL;
	struct segment *segment = NULL;
	char *p = NULL;

	while(!feof(maps) && fgets(line, MAX_MAPS_LINE_LENGTH, maps) != NULL) {
		segment = malloc(sizeof(*segment));
		if(!segment && (err = libredirect_error_nomem)) {
			LOG(libredirect_log_error, "malloc %d bytes failed", sizeof(*segment));
			goto exit;
		}
		memset(segment, 0, sizeof(*segment));

		p = strtok(line, " ");
		if(!p || sscanf(p, "%p-%p", &segment->start, &segment->end) < 2) {
			LOG(libredirect_log_error, "%s malformed", map_path);
			goto malformed;
		}

		p = strtok(NULL, " ");
		if(!p || strlen(p) < 4) {
			LOG(libredirect_log_error, "%s malformed", map_path);
			goto malformed;
		}
		if(p[0] == 'r')
			segment->permission |= permission_read;
		if(p[1] == 'w')
			segment->permission |= permission_write;
		if(p[2] == 'x')
			segment->permission |= permission_execute;

		p = strtok(NULL, " ");
		if(!p) {
			LOG(libredirect_log_error, "%s malformed", map_path);
			goto malformed;
		}

		p = strtok(NULL, " ");
		if(!p) {
			LOG(libredirect_log_error, "%s malformed", map_path);
			goto malformed;
		}

		p = strtok(NULL, " ");
		if(!p) {
			LOG(libredirect_log_error, "%s malformed", map_path);
			goto malformed;
		}

		p = strtok(NULL, " ");
		if(!p) {
			LOG(libredirect_log_error, "%s malformed", map_path);
			goto malformed;
		}
		p[strlen(p)-1] = '\0';
		segment->path = strdup(p);
		if(!segment->path && (err = libredirect_error_nomem)) {
			LOG(libredirect_log_error, "strdup failed");
			goto exit;
		}

		LOG(libredirect_log_info, "found segment %p-%p with permission %d", segment->start, segment->end, segment->permission);

		segment->next = segments;
		segments = segment;
		continue;

		malformed: /* if this happens, something is obviously wrong with the code. */
			err = libredirect_error_segments;
			goto exit;
	}

	if(ferror(maps) && (err = libredirect_error_syscall)) {
		LOG(libredirect_log_error, "reading from %s failed: %s (%d)", map_path, strerror(errno), errno);
		goto exit;
	}

	*seg = segments;

exit:
	if(maps)
		fclose(maps);

	if(err && segments)
		destroy_segments(segments);

	return err;
}

int destroy_segments(struct segment *segment) {
	LOG(libredirect_log_call, __FUNCTION__);
	int err = libredirect_error_none;
	struct segment *t = NULL;
	while(segment) {
		t = segment->next;
		if(segment->path)
			free(segment->path);
		free(segment);
		segment = t;
	}

	return err;
}

int init_bfd(const char *exe_path, bfd **bbfd) {
	LOG(libredirect_log_call, __FUNCTION__);
	bfd *abfd = NULL;
	int err = libredirect_error_none;
	bfd_error_type bfd_err;

	bfd_init();
	LOG(libredirect_log_info, "open executable %s", exe_path);
	abfd = bfd_openr(exe_path, NULL);

	if(!abfd) {
		bfd_err = bfd_get_error();
		LOG(libredirect_log_error, "bfd_openr failed: %d", bfd_err);
		switch(bfd_err) {
			case bfd_error_no_memory:
				err = libredirect_error_nomem; break;
			case bfd_error_invalid_target:
				err = libredirect_error_executable; break;
			case bfd_error_system_call:
				err = libredirect_error_syscall; break;
			default:
				err = libredirect_error_unknown;
		}
		goto exit;
	}

	LOG(libredirect_log_info, "check executable format");
	if(!bfd_check_format(abfd, bfd_object)) {
		bfd_err = bfd_get_error();
		assert(bfd_err != bfd_error_invalid_operation);
		LOG(libredirect_log_error, "bfd_check_format failed: %d", bfd_err);

		switch(bfd_err) {
			case bfd_error_system_call:
				err = libredirect_error_syscall; break;
			case bfd_error_file_not_recognized:
			case bfd_error_file_ambiguously_recognized:
				err = libredirect_error_executable; break;
			default:
				err = libredirect_error_unknown;
		}
		goto exit;
	}

	const bfd_arch_info_type *info = bfd_get_arch_info(abfd);
	assert(info != NULL);
	LOG(libredirect_log_info, "executable format: arch %s, mach %s", info->arch_name, bfd_printable_arch_mach(info->arch, info->mach));

	*bbfd = abfd;

exit:
	return err;
}

int destroy_bfd(bfd *abfd) {
	LOG(libredirect_log_call, __FUNCTION__);
	if(!bfd_close(abfd))
		return libredirect_error_none; /* FIXME: what errors can occure? */
	return libredirect_error_none;
}

int init_disassembler(bfd *abfd, disassemble_info **dis_info) {
	LOG(libredirect_log_call, __FUNCTION__);
	int err = libredirect_error_none;
	disassemble_info *dis = malloc(sizeof(*dis));
	if(!dis) {
		LOG(libredirect_log_error, "malloc %d bytes failed", sizeof(*dis));
		err = libredirect_error_nomem;
		goto exit;
	}

	memset(dis, 0, sizeof(*dis));

	init_disassemble_info(dis, NULL, null_fprintf);
	dis->arch = bfd_get_arch(abfd);
	dis->mach = bfd_get_mach(abfd);
	disassemble_init_for_target(dis);

	*dis_info = dis;

exit:
	return err;
}

int destroy_disassembler(disassemble_info *dis_info) {
	LOG(libredirect_log_call, __FUNCTION__);
	assert(dis_info != NULL);
	free(dis_info);
	return libredirect_error_none;
}

int get_disassemble_function(bfd *abfd, disassembler_ftype *dis_asm) {
	LOG(libredirect_log_call, __FUNCTION__);
	/* FIXME: doc: Fetch the disassembler for a given BFD, if that support is available.
	 * what if not available?
	 */
	*dis_asm = disassembler(abfd);
	return libredirect_error_none;
}

int get_executable_path(char **ep) {
	LOG(libredirect_log_call, __FUNCTION__);
	int err = libredirect_error_none;
	char proc[PATH_MAX + 1];
	char buf[PATH_MAX + 1];
	snprintf(proc, PATH_MAX, "/proc/%d/exe", getpid());
	printf("proc: %s\n", proc);
	LOG(libredirect_log_info, "symlink to executable is %s", proc);

	char *exe_path = realpath(proc, buf);
	*ep = strdup(exe_path);
	if(!(*ep)) {
		LOG(libredirect_log_error, "strdup failed (Out of memory)");
		err = libredirect_error_nomem;
	}
	LOG(libredirect_log_info, "executable path is %s", exe_path);

	return err;
}

__PUBLIC int libredirect_init() {
	LOG(libredirect_log_call, __FUNCTION__);
	int err = libredirect_error_none;

	if((libredirect.status & status_init) && (err = libredirect_error_already)) {
		LOG(libredirect_log_error, "libredirect is already initialized");
		goto error;
	}

	if((err = get_executable_path(&libredirect.executable_path)))
		goto error;

	if((err = init_bfd(libredirect.executable_path, &libredirect.abfd)))
		goto error;

	if((err = init_disassembler(libredirect.abfd, &libredirect.dis_info)))
		goto error;

	if((err = get_disassemble_function(libredirect.abfd, &libredirect.disassemble)))
		goto error;

	libredirect.status |= status_init;
	goto exit;

error:
	if(libredirect.abfd) {
		destroy_bfd(libredirect.abfd);
		libredirect.abfd = NULL;
	}
	if(libredirect.dis_info) {
		destroy_disassembler(libredirect.dis_info);
		libredirect.dis_info = NULL;
	}
exit:
	return err;
}

__PUBLIC int libredirect_destroy() {
	LOG(libredirect_log_call, __FUNCTION__);
	int err = libredirect_error_none;

	if(!(libredirect.status & status_init) && (err = libredirect_error_already)) {
		LOG(libredirect_log_error, "libredirect is not initialized");
		goto exit;
	}

	if(libredirect.abfd) {
		destroy_bfd(libredirect.abfd);
		libredirect.abfd = NULL;
	}
	if(libredirect.dis_info) {
		destroy_disassembler(libredirect.dis_info);
		libredirect.dis_info = NULL;
	}
	if(libredirect.executable_path) {
		free(libredirect.executable_path);
		libredirect.executable_path = NULL;
	}
	libredirect.disassemble = NULL;

	libredirect.status ^= status_init;

exit:
	return err;
}

__PUBLIC int libredirect_redirect(void *from, void *to, void **new) {
	LOG(libredirect_log_call, __FUNCTION__);
	int err = libredirect_error_none;

	libredirect.dis_info->buffer = NULL;
	struct segment *segments = NULL;
	unsigned char *stub = NULL;
	void *jmp_instr = NULL;

	if(!(libredirect.status & status_init) && (err = libredirect_error_already)) {
		LOG(libredirect_log_error, "libredirect is not initialized");
		goto exit;
	}

	/* atm, we can't handle more than 32bit addresses */
	void *func_distance = (void *)((from > to) ? from - to : to - from);
	if(func_distance > (void *)0xffffffff && (err = libredirect_error_distant)) {
		LOG(libredirect_log_error, "cannot redirect from %p to %p because the difference is too big (> 2^32)", from, to);
		goto exit;
	}

	if((err = init_segments(&segments)))
		goto exit;

	size_t jmp_size = 0;
	init_jump_instruction(from, to, &jmp_instr, &jmp_size);

	libredirect.dis_info->read_memory_func = buffer_read_memory;
	libredirect.dis_info->buffer_length = jmp_size + MAX_ASM_INST_LENGTH;
	libredirect.dis_info->buffer = malloc(libredirect.dis_info->buffer_length);

	if(!libredirect.dis_info->buffer && (err = libredirect_error_nomem)) {
		LOG(libredirect_log_error, "malloc %d bytes failed", libredirect.dis_info->buffer_length);
		goto exit;
	}

	if((err = read_memory(segments, from, libredirect.dis_info->buffer_length, libredirect.dis_info->buffer)))
		goto exit;

	/* after this instruction code should not fail or we have to restore to a point before this */
	if((err = write_memory(segments, from, jmp_size, jmp_instr)))
		goto exit;

	struct segment *curr_seg = segments;
	while(curr_seg && (curr_seg->start > from || curr_seg->end < from))
		curr_seg = curr_seg->next;
	if(!curr_seg && (err = libredirect_error_segments)) {
		LOG(libredirect_log_error, "no segment found at %p", from);
		goto restore_and_exit;
	}

	errno = 0;
	long pagesize = sysconf(_SC_PAGE_SIZE);
	assert(pagesize != -1 && errno == 0);

	void *stub_buffer = mmap(curr_seg->end, pagesize, PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_PRIVATE, -1, 0);
	if(stub_buffer == MAP_FAILED && (err = libredirect_error_syscall)) {
		LOG(libredirect_log_error, "allocating %d bytes of memory with mmap at %p failed", pagesize, curr_seg->end);
		goto restore_and_exit;
	}

	size_t full_instr_size = 0;
	while(full_instr_size < jmp_size) {
		full_instr_size += libredirect.disassemble(full_instr_size, libredirect.dis_info);
	}

	destroy_jump_instruction(jmp_instr);
	init_jump_instruction(stub_buffer + full_instr_size, from+full_instr_size, &jmp_instr, &jmp_size);

	size_t stub_size = full_instr_size + jmp_size;
	stub = malloc(stub_size);
	if(!stub && (err = libredirect_error_nomem)) {
		LOG(libredirect_log_error, "malloc %d bytes failed", stub_size);
		goto restore_and_exit;
	}
	memcpy(stub, libredirect.dis_info->buffer, full_instr_size);
	memcpy(stub + full_instr_size, jmp_instr, jmp_size);

	func_distance = (void *)((from > stub_buffer) ? from - stub_buffer : stub_buffer - from);
	if(func_distance > (void *)0xffffffff && (err = libredirect_error_distant)) {
		LOG(libredirect_log_error, "stub (%p) is more than 2^32 bytes away from original function (%p)", stub, from);
		goto restore_and_exit;
	}

	memcpy(stub_buffer, stub, stub_size);
	if(new)  {
		*new = stub_buffer;
	}

	goto exit;

restore_and_exit:
	/* try to restore default state */
	write_memory(segments, from, jmp_size, libredirect.dis_info->buffer);

exit:
	if(stub) {
		free(stub);
		stub = NULL;
	}
	if(jmp_instr) {
		destroy_jump_instruction(jmp_instr);
		jmp_instr = NULL;
	}
	if(segments) {
		destroy_segments(segments);
		segments = NULL;
	}
	if(libredirect.dis_info->buffer) {
		free(libredirect.dis_info->buffer);
		libredirect.dis_info->buffer = NULL;
	}
	return err;
}

__PUBLIC char *libredirect_strerror(int errnum) {
	switch(errnum) {
		case libredirect_error_none:
			return "No error";
		case libredirect_error_already:
			return "The library is already initalized";
		case libredirect_error_nomem:
			return "Out of memory";
		case libredirect_error_syscall:
			return "System call failed";
		case libredirect_error_executable:
			return "Proccess has an invalid executable";
		case libredirect_error_segments:
			return "Pointer not in any segment";
		case libredirect_error_distant:
			return "Distance of the addresses exceeds boundaries";
		case libredirect_error_unknown:
		default:
			return "Unknown error";
	}
}

__PUBLIC int libredirect_set_log(void (*log_func)(const char *, int, int, const char *), int log_level) {
	libredirect.log_func = log_func;
	libredirect.log_level = log_level;
	return libredirect_error_none;
}

#if 0
void (*glFinish_orig)();
void (*glxSwapBuffers_orig)(void *dsp, unsigned int drawable);

void glFinish() {
	assert(glFinish_orig != NULL);
	printf("finish\n");
}

void glxSwapBuffers(void *dsp, unsigned int drawable) {
	assert(glxSwapBuffers_orig != NULL);
	usleep(500000);
	fprintf(stderr, "swap buffers (orig: %p)\n", glxSwapBuffers_orig);
	glxSwapBuffers_orig(dsp, drawable);
}

__PUBLIC __attribute__((constructor)) void libredirect_test() {

	int err = 0;
	void *gl = dlopen("libGL.so.1", RTLD_LAZY);
	assert(gl != NULL);

	void *(*glxGetProcAddress)(const char *);
	glxGetProcAddress = dlsym(gl, "glXGetProcAddress");
	assert(glxGetProcAddress != NULL);

	void *glFinish_addr = glxGetProcAddress("glFinish");
	void *glFinish_addr2 = dlsym(dlopen(NULL, RTLD_LAZY), "glFinish");
	assert(glFinish_addr != NULL);
	void *glxSwapBuffers_addr =  glxGetProcAddress("glXSwapBuffers");
	void *glxSwapBuffers_addr2 = dlsym(dlopen(NULL, RTLD_LAZY), "glXSwapBuffers");
	assert(glxSwapBuffers_addr != NULL);

	glFinish_orig = NULL;
	glxSwapBuffers_orig = NULL;

	libredirect_init();

	if(glFinish_addr2) {
		printf("redirect from %p to %p\n", glFinish_addr2, glFinish);
		if((err = libredirect_redirect(glFinish_addr2, glFinish, (void **)&glFinish_orig))) {
			printf("libredirect_redirect failed: %d\n", err);
		}
	}
	else {
		printf("redirect from %p to %p\n", glFinish_addr, glFinish);
		if((err = libredirect_redirect(glFinish_addr, glFinish, (void **)&glFinish_orig))) {
			printf("libredirect_redirect failed: %d\n", err);
		}
	}

	if(glxSwapBuffers_addr2) {
		printf("redirect from %p to %p\n", glxSwapBuffers_addr2, glxSwapBuffers);
		if((err = libredirect_redirect(glxSwapBuffers_addr2, glxSwapBuffers, (void **)&glxSwapBuffers_orig))) {
			printf("libredirect_redirect failed: %d\n", err);
		}
	}
	else {
		printf("redirect from %p to %p\n", glxSwapBuffers_addr, glxSwapBuffers);
		if((err = libredirect_redirect(glxSwapBuffers_addr, glxSwapBuffers, (void **)&glxSwapBuffers_orig))) {
			printf("libredirect_redirect failed: %d\n", err);
		}
	}


	libredirect_destroy();
}
#endif
