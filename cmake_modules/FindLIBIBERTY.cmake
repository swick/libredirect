# set(LIBIBERTY_PREFERE_STATIC True) if you want to prefere the static library
# set(LIBIBERTY_SEARCH_LIB "/path/to/dir") to search for the library in /path/to/dir first

if(LIBIBERTY_PREFERE_STATIC)
	set(LIBIBERTY_SEARCHORDER libiberty.a libiberty.so)
else()
	set(LIBIBERTY_SEARCHORDER libiberty.so libiberty.a)
endif()

find_library(LIBIBERTY_LIBRARY NAMES ${LIBIBERTY_SEARCHORDER} HINTS ${LIBIBERTY_SEARCH_LIB})
find_path(LIBIBERTY_INCLUDE_DIR dis-asm.h ${LIBIBERTY_SEARCH_PATH})

if(LIBIBERTY_INCLUDE_DIR AND LIBIBERTY_LIBRARY)
	set(LIBIBERTY_FOUND TRUE)
endif()

if(LIBIBERTY_FOUND)
	if(NOT LIBIBERTY_FIND_QUIETLY)
		MESSAGE(STATUS "Found libiberty: ${LIBIBERTY_LIBRARY}")
	endif()
else()
	if(LIBIBERTY_FIND_REQUIRED)
		MESSAGE(FATAL_ERROR "Could not find libiberty")
	endif()
endif()

