#ifndef LIBREDIRECT_H__
#define LIBREDIRECT_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief error codes
 */
typedef enum {
	/** no error */
	libredirect_error_none = 0,
	/** unkown error */
	libredirect_error_unknown,
	/** already/not initialized */
	libredirect_error_already,
	/** out of memory */
	libredirect_error_nomem,
	/** system call failed */
	libredirect_error_syscall,
	/** invalid executable format */
	libredirect_error_executable,
	/** no segment for address found */
	libredirect_error_segments,
	/** distance of addresses is too high */
	libredirect_error_distant
} libredirect_error;

/**
 * \brief log level
 */
typedef enum {
	/** log errors */
	libredirect_log_error = (1 << 0),
	/** log warnings */
	libredirect_log_warning = (1 << 1),
	/** log function calls */
	libredirect_log_call = (1 << 2),
	/** log debug information */
	libredirect_log_info = (1 << 3),
	/** log all */
	libredirect_log_all = (1 << 4)-1
} libredirect_log_level;

/** 
 * \brief initialize libredirect's data structures
 * \return error code
 */
int libredirect_init();

/** 
 * \brief destroy libredirect's data structures
 * \return error code
 */
int libredirect_destroy();

/**
 * \brief redirects function calls
 * \param from address of the function which will be redirected
 * \param to address of the function to redirect to
 * \param new pointer to store the new address of the overwritten function or NULL
 * \return error code
 * \note the function addresses should be the real addresses and not an
 *       address to a symbol
 */
int libredirect_redirect(void *from, void *to, void **new);

/**
 * \brief get the string representation of an error code
 * \param errnum error code
 * \return string representation
 */
char *libredirect_strerror(int errnum);

/**
 * \brief set a log function and the log level
 * \param log_func a function
 * \param log_level bitmask of libredirect_log_level for which to call log_func
 * \return error code
 * \note can be set before libredirect_init
 */
int libredirect_set_log(void (*log_func)(const char *, int, int, const char *), int log_level);

#ifdef __cplusplus
}
#endif

#endif
