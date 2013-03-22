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

#include "redirect.h"
#include "arch.h"

#define UNUSED(X) (void)(X)
#define __PUBLIC __attribute__((visibility("default")))
#define MAX_ASM_INST_LENGTH 32 /* wild guess, have no clue */
#define MAX_MAPS_LINE_LENGTH 4096

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
} libredirect =  {0};

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

int destroy_segments(struct segment *segment);

int null_fprintf(void *f, const char *str, ...) {
	UNUSED(f);
	UNUSED(str);
	return 0;
}

int read_memory(const struct segment *segment, const void *at, const size_t length, void *buf) {
	int err = libredirect_error_none;
	assert(segment != NULL);

	while(segment) {
		if(at < segment->end && at >= segment->start)
			break;
		segment = segment->next;
	}
	if(!segment && (err = libredirect_error_segments))
		goto exit;

	if(segment->permission & permission_read) {
		goto read;
	}

	int permission =
		(segment->permission & permission_read) ? PROT_READ : 0 |
		(segment->permission & permission_write) ? PROT_WRITE : 0 |
		(segment->permission & permission_execute) ? PROT_EXEC : 0;

	int n_perm = permission | PROT_READ;

	if(mprotect(segment->start, segment->end - segment->start, n_perm) < 0) {
		err = libredirect_error_syscall;
		goto exit;
	}

read:
	memcpy(buf, at, length);

	/*  restore permission */
	if(!(segment->permission & permission_read)) {
		if(mprotect(segment->start, segment->end - segment->start, permission) < 0) {
			err = libredirect_error_syscall;
			goto exit;
		}
	}

exit:
	return err;
}

int write_memory(const struct segment *segment, void *at, const size_t length, const void *buf) {
	int err = libredirect_error_none;
	assert(segment != NULL);

	while(segment) {
		if(at < segment->end && at >= segment->start)
			break;
		segment = segment->next;
	}
	if(!segment && (err = libredirect_error_segments))
		goto exit;

	if(segment->permission & permission_write)
		goto write;

	int permission =
		((segment->permission & permission_read) ? PROT_READ : 0) |
		((segment->permission & permission_write) ? PROT_WRITE : 0) |
		((segment->permission & permission_execute) ? PROT_EXEC : 0);

	int n_perm = permission | PROT_WRITE;

	if(mprotect(segment->start, segment->end - segment->start, n_perm) < 0) {
		err = libredirect_error_syscall;
		goto exit;
	}

write:
	memcpy(at, buf, length);

	/*  restore permission */
	if(!(segment->permission & permission_write)) {
		if(mprotect(segment->start, segment->end - segment->start, permission) < 0) {
			err = libredirect_error_syscall;
			goto exit;
		}
	}

exit:
	return err;
}

int init_segments(struct segment **seg) {
	int err = libredirect_error_none;
	FILE *maps = NULL;

	char map_path[PATH_MAX + 1];
	snprintf(map_path, PATH_MAX, "/proc/%d/maps", getpid());

	maps = fopen(map_path, "r");
	if(!maps && (err = libredirect_error_syscall))
		goto exit;

	char line[MAX_MAPS_LINE_LENGTH];
	struct segment *segments = NULL;
	struct segment *segment = NULL;
	char *p = NULL;

	while(!feof(maps) && fgets(line, MAX_MAPS_LINE_LENGTH, maps) != NULL) {
		segment = malloc(sizeof(*segment));
		if(!segment && (err = libredirect_error_nomem))
			goto exit;
		memset(segment, 0, sizeof(*segment));

		p = strtok(line, " ");
		if(!p || sscanf(p, "%p-%p", &segment->start, &segment->end) < 2)
			goto malformed;

		p = strtok(NULL, " ");
		if(!p || strlen(p) < 4)
			goto malformed;
		if(p[0] == 'r')
			segment->permission |= permission_read;
		if(p[1] == 'w')
			segment->permission |= permission_write;
		if(p[2] == 'x')
			segment->permission |= permission_execute;

		p = strtok(NULL, " ");
		if(!p)
			goto malformed;

		p = strtok(NULL, " ");
		if(!p)
			goto malformed;

		p = strtok(NULL, " ");
		if(!p)
			goto malformed;

		p = strtok(NULL, " ");
		if(!p)
			goto malformed;
		p[strlen(p)-1] = '\0';
		segment->path = strdup(p);
		if(!segment->path && (err = libredirect_error_nomem))
			goto exit;

		segment->next = segments;
		segments = segment;
		continue;

		malformed: /* if this happens, something is obviously wrong with the code. */
			err = libredirect_error_segments;
			goto exit;
	}

	if(ferror(maps) && (err = libredirect_error_syscall))
		goto exit;

	*seg = segments;

exit:
	if(maps)
		fclose(maps);

	if(err && segments)
		destroy_segments(segments);

	return err;
}

int destroy_segments(struct segment *segment) {
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
	bfd *abfd = NULL;
	int err = libredirect_error_none;
	bfd_error_type bfd_err;

	bfd_init();
	abfd = bfd_openr(exe_path, NULL);

	if(!abfd) {
		bfd_err = bfd_get_error();
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

	if(!bfd_check_format(abfd, bfd_object)) {
		bfd_err = bfd_get_error();
		assert(bfd_err != bfd_error_invalid_operation);

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

	*bbfd = abfd;

exit:
	return err;
}

int destroy_bfd(bfd *abfd) {
	if(!bfd_close(abfd))
		return libredirect_error_none; /* FIXME: what errors can occure? */
	return libredirect_error_none;
}

int init_disassembler(bfd *abfd, disassemble_info **dis_info) {
	int err = libredirect_error_none;
	disassemble_info *dis = malloc(sizeof(*dis));
	if(!dis) {
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
	assert(dis_info != NULL);
	free(dis_info);
	return libredirect_error_none;
}

int get_disassemble_function(bfd *abfd, disassembler_ftype *dis_asm) {
	/* FIXME: doc: Fetch the disassembler for a given BFD, if that support is available.
	 * what if not available?
	 */
	*dis_asm = disassembler(abfd);
	return libredirect_error_none;
}

int get_executable_path(char **ep) {
	int err = libredirect_error_none;
	char proc[PATH_MAX + 1];
	char buf[PATH_MAX + 1];
	snprintf(proc, PATH_MAX, "/proc/%d/exe", getpid());

	char *exe_path = realpath(proc, buf);
	*ep = strdup(exe_path);
	if(!(*ep))
		err = libredirect_error_nomem;

	return err;
}

__PUBLIC int libredirect_init() {
	int err = libredirect_error_none;

	if((libredirect.status & status_init) && (err = libredirect_error_already))
		goto error;

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
	int err = libredirect_error_none;

	if(!(libredirect.status & status_init) && (err = libredirect_error_already))
		goto exit;

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
	int err = libredirect_error_none;

	libredirect.dis_info->buffer = NULL;
	struct segment *segments = NULL;
	unsigned char *stub = NULL;
	void *jmp_instr = NULL;

	if(!(libredirect.status & status_init) && (err = libredirect_error_already))
		goto exit;

	/* atm, we can't handle more than 32bit addresses */
	void *func_distance = (void *)((from > to) ? from - to : to - from);
	if(func_distance > (void *)0xffffffff && (err = libredirect_error_distant))
		goto exit;

	if((err = init_segments(&segments)))
		goto exit;

	size_t jmp_size = 0;
	init_jump_instruction(from, to, &jmp_instr, &jmp_size);

	libredirect.dis_info->read_memory_func = buffer_read_memory;
	libredirect.dis_info->buffer_length = jmp_size + MAX_ASM_INST_LENGTH;
	libredirect.dis_info->buffer = malloc(libredirect.dis_info->buffer_length);

	if(!libredirect.dis_info->buffer && (err = libredirect_error_nomem))
		goto exit;

	if((err = read_memory(segments, from, libredirect.dis_info->buffer_length, libredirect.dis_info->buffer)))
		goto exit;

	/* after this instruction code should not fail or we have to restore to a point before this */
	if((err = write_memory(segments, from, jmp_size, jmp_instr)))
		goto exit;

	struct segment *curr_seg = segments;
	while(curr_seg && (curr_seg->start > from || curr_seg->end < from))
		curr_seg = curr_seg->next;
	if(!curr_seg && (err = libredirect_error_segments))
		goto restore_and_exit;

	errno = 0;
	long pagesize = sysconf(_SC_PAGE_SIZE);
	assert(pagesize != -1 && errno == 0);

	void *stub_buffer = mmap(curr_seg->end, pagesize, PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_PRIVATE, -1, 0);
	if(stub_buffer == MAP_FAILED && (err = libredirect_error_syscall))
		goto restore_and_exit;

	size_t full_instr_size = 0;
	while(full_instr_size < jmp_size) {
		full_instr_size += libredirect.disassemble(full_instr_size, libredirect.dis_info);
	}

	destroy_jump_instruction(jmp_instr);
	init_jump_instruction(stub_buffer + full_instr_size, from+full_instr_size, &jmp_instr, &jmp_size);

	size_t stub_size = full_instr_size + jmp_size;
	stub = malloc(stub_size);
	if(!stub && (err = libredirect_error_nomem))
		goto restore_and_exit;
	memcpy(stub, libredirect.dis_info->buffer, full_instr_size);
	memcpy(stub + full_instr_size, jmp_instr, jmp_size);

	func_distance = (void *)((from > stub_buffer) ? from - stub_buffer : stub_buffer - from);
	if(func_distance > (void *)0xffffffff && (err = libredirect_error_distant))
		goto restore_and_exit;

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
