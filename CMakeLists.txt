project (data-xfers-test-app C CXX)

set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")

add_executable (data-xfers-test-app src/main.c)

include_directories (${CMAKE_CURRENT_SOURCE_DIR}/inc)


set (
        CMAKE_C_FLAGS
            "${CMAKE_C_FLAGS} \
            -Wall \
            -Wextra \
            -Wunused \
            -Wsign-conversion \
            -Wnull-dereference \
            -Wdouble-promotion \
            -Wformat=2 \
            -Wno-unused-parameter \
            -Werror \
            -Wduplicated-cond \
            -Wduplicated-branches \
            -Wlogical-op \
            -Wshadow \
            -Wmisleading-indentation \
            "
            )

install (TARGETS data-xfers-test-app  DESTINATION bin)

