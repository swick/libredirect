# set(OPCODES_PREFERE_STATIC True) if you want to prefere the static library
# set(OPCODES_SEARCH_LIB "/path/to/dir") to search for the library in /path/to/dir first

if(OPCODES_PREFERE_STATIC)
	set(OPCODES_SEARCHORDER libopcodes.a libopcodes.so)
	# then do the same for the dependency, if not defined otherwise
	if(NOT DEFINED BFD_PREFERE_STATIC)
		set(BFD_PREFERE_STATIC True)
	endif()
else()
	set(OPCODES_SEARCHORDER libopcodes.so libopcodes.a)
endif()

if(DEFINED OPCODES_SEARCH_LIB AND NOT DEFINED BFD_SEARCH_LIB)
	set(BFD_SEARCH_LIB ${OPCODES_SEARCH_LIB})
endif()

find_library(OPCODES_LIBRARY NAMES ${OPCODES_SEARCHORDER} HINTS ${OPCODES_SEARCH_LIB})
find_path(OPCODES_INCLUDE_DIR dis-asm.h ${OPCODES_SEARCH_PATH})

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
set(OPCODES_LIBRARY ${OPCODES_LIBRARY} ${ZLIB_LIBRARIES} ${CMAKE_DL_LIBS} ${BFD_LIBRARY})
