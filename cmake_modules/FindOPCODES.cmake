# set(OPCODES_PREFER_STATIC True) if you want to prefer the static library

if(OPCODES_PREFER_STATIC)
	set(OPCODES_SEARCHORDER libopcodes.a libopcodes.so)
	# then do the same for the dependency, if not defined otherwise
	if(NOT DEFINED BFD_PREFER_STATIC)
		set(BFD_PREFER_STATIC True)
	endif()
	if(NOT DEFINED ZLIB_PREFER_STATIC)
		set(ZLIB_PREFER_STATIC True)
	endif()
else()
	set(OPCODES_SEARCHORDER libopcodes.so libopcodes.a)
endif()

find_library(OPCODES_LIBRARY NAMES ${OPCODES_SEARCHORDER})
find_path(OPCODES_INCLUDE_DIR dis-asm.h)

if(OPCODES_INCLUDE_DIR AND OPCODES_LIBRARY)
	set(OPCODES_FOUND TRUE)
endif()

if(OPCODES_FOUND)
	if(NOT OPCODES_FIND_QUIETLY)
		MESSAGE(STATUS "Found opcodes: ${OPCODES_LIBRARY}")
	endif()
else()
	if(OPCODES_FIND_REQUIRED)
		MESSAGE(FATAL_ERROR "Could not find opcodes")
	endif()
endif()

find_package(ZLIB REQUIRED)
find_package(BFD REQUIRED)
set(OPCODES_INCLUDE_DIR ${OPCODES_INCLUDE_DIR} ${ZLIB_INCLUDE_DIRS} ${BFD_INCLUDE_DIR})
set(OPCODES_LIBRARY ${OPCODES_LIBRARY} ${ZLIB_LIBRARY} ${CMAKE_DL_LIBS} ${BFD_LIBRARY})
