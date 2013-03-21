
set(ZLIB_SEARCHORDER z zlib zdll zlib1 zlibd zlibd1)
set(ZLIB_STATIC_LIBS libz.a libzlib.a libzdll.a libzlib1.a libzlibd.a vzlibd1.a)
set(ZLIB_DYNAMIC_LIBS libz.so.1 libz.so libzlib.so libzdll.so libzlib1.so libzlibd.so vzlibd1.so)
if(ZLIB_PREFER_STATIC)
	set(ZLIB_SEARCHORDER ${ZLIB_STATIC_LIBS} ${ZLIB_DYNAMIC_LIBS} ${ZLIB_SEARCHORDER})
else()
	set(ZLIB_SEARCHORDER ${ZLIB_DYNAMIC_LIBS} ${ZLIB_STATIC_LIBS} ${ZLIB_SEARCHORDER})
endif()

message("${CMAKE_LIBRARY_PATH}")
find_library(ZLIB_LIBRARY NAMES libz.so.1)
find_path(ZLIB_INCLUDE_DIR zlib.h)

if(ZLIB_INCLUDE_DIR AND ZLIB_LIBRARY)
	set(ZLIB_FOUND TRUE)
endif()

if(ZLIB_FOUND)
	if(NOT ZLIB_FIND_QUIETLY)
		MESSAGE(STATUS "Found zlib: ${ZLIB_LIBRARY}")
	endif()
else()
	if(ZLIB_FIND_REQUIRED)
		MESSAGE(FATAL_ERROR "Could not find zlib")
	endif()
endif()

