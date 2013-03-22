#ifndef LIBREDIRECT_H__
#define LIBREDIRECT_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
 *
 */
typedef enum {
	libredirect_error_none = 0,
	libredirect_error_unknown,
	libredirect_error_already,
	libredirect_error_nomem,
	libredirect_error_syscall,
	libredirect_error_executable,
	libredirect_error_segments,
	libredirect_error_distant
} libredirect_error;

typedef enum {
	libredirect_log_error = (1 << 0),
	libredirect_log_warning = (1 << 1),
	libredirect_log_call = (1 << 2),
	libredirect_log_info = (1 << 3),
	libredirect_log_all = (1 << 4)-1
} libredirect_log_level;

/*
 *
 */
int libredirect_init();

/*
 *
 */
int libredirect_destroy();

/* \brief redirects function calls from the function locatet at \param from
 *        to the function located at \param to and saves the new address
 *        of function \param from in \param new
 */
int libredirect_redirect(void *from, void *to, void **new);

/*
 *
 */
char *libredirect_strerror(int errnum);

/* \note can be set before libredirect_init
 * log_func(const char *file, int line, int log_level, const char *log)
 */
int libredirect_set_log(void (*log_func)(const char *, int, int, const char *), int log_level);

#ifdef __cplusplus
}
#endif

#endif
