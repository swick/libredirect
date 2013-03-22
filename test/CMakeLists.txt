enable_testing()

# set -fvisibility=default and -O0 to assure that we can find func_a and func_b with dlsym
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=default -O0")
include_directories(${PROJECT_SOURCE_DIR})

add_executable(test_executable test_executable.c)
target_link_libraries(test_executable redirect dl)

add_test(test_exec ${CMAKE_CURRENT_BINARY_DIR}/test_executable)

