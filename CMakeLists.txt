
cmake_minimum_required(VERSION 2.8)
project(libredirect)

#option CMAKE_LIBRARY_PATH
 option(LIBRARY_PREFER_STATIC "use static libraries if possible" ON)
 option(BUILD_TESTS "build tests" ON)

if(NOT DEFINED CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "Debug")
endif()

set(BASE_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake_modules")


set(CMAKE_C_FLAGS "${BASE_C_FLAGS} -Wall -Wextra -fvisibility=hidden -fPIC")

if(${CMAKE_C_FLAGS} MATCHES "-m32")
	set_property(GLOBAL PROPERTY FIND_LIBRARY_USE_LIB64_PATHS OFF)
	set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} /lib/i386-linux-gnu)
endif()

if(LIBRARY_PREFER_STATIC)
	set(OPCODES_PREFER_STATIC True)
endif()
find_package(OPCODES REQUIRED)

set(REDIRECT_INCLUDES
	${OPCODES_INCLUDE_DIR})

set(REDIRECT_LIBS
	${OPCODES_LIBRARY})

set(REDIRECT_SRC
	redirect.c
	arch/x86.c)

add_library(redirect SHARED ${REDIRECT_SRC})
include_directories(${REDIRECT_INCLUDES})
target_link_libraries(redirect ${REDIRECT_LIBS})

IF(BUILD_TESTS)
	add_subdirectory(test)
ENDIF()

