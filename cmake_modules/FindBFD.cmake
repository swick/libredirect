# set(BFD_PREFER_STATIC True) if you want to prefer the static library

if(BFD_PREFER_STATIC)
	set(BFD_SEARCHORDER libbfd.a libbfd.so)
	# then do the same for the dependency, if not defined otherwise
	if(NOT DEFINED LIBIBERTY_PREFER_STATIC)
		set(LIBIBERTY_PREFER_STATIC True)
	endif()
else()
	set(BFD_SEARCHORDER libbfd.so libbfd.a)
endif()

find_library(BFD_LIBRARY NAMES ${BFD_SEARCHORDER})
find_path(BFD_INCLUDE_DIR bfd.h)

if(BFD_INCLUDE_DIR AND BFD_LIBRARY)
	set(BFD_FOUND TRUE)
endif()

if(BFD_FOUND)
	if(NOT BFD_FIND_QUIETLY)
		MESSAGE(STATUS "Found bfd: ${BFD_LIBRARY}")
	endif()
else()
	if(BFD_FIND_REQUIRED)
		MESSAGE(FATAL_ERROR "Could not find bfd")
	endif()
endif()

find_package(LIBIBERTY REQUIRED)
set(BFD_INCLUDE_DIR ${BFD_INCLUDE_DIR} ${LIBIBERTY_INCLUDE_DIR})
set(BFD_LIBRARY ${BFD_LIBRARY} ${LIBIBERTY_LIBRARY})


