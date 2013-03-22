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

#ifdef __cplusplus
}
#endif

#endif
