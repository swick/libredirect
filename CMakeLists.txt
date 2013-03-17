cmake_minimum_required(VERSION 2.8)
project(libredirect)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden -fPIC")
set(REDIRECT_LIBS
	z
	dl
	${PROJECT_SOURCE_DIR}/lib/libopcodes.a
	${PROJECT_SOURCE_DIR}/lib/libbfd.a
	${PROJECT_SOURCE_DIR}/lib/libiberty.a)

add_library(redirect SHARED
	redirect.c
	arch/amd64.c)
target_link_libraries(redirect ${REDIRECT_LIBS})

add_subdirectory(test)
