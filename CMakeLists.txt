cmake_minimum_required(VERSION 3.10)
project(qlib_sample_server)

# Set the C standard
set(CMAKE_C_STANDARD 11)

# Find the PThreads package
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/platform
    ${CMAKE_SOURCE_DIR}/qconf
    ${CMAKE_SOURCE_DIR}/remote
    ${CMAKE_SOURCE_DIR}/samples
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/utils
    ${CMAKE_SOURCE_DIR}/samples/remote
)

# Source files
set(SOURCE_FILES
    platform/qlib_platform.c
    remote/qlib_server.c
    qconf/qconf.c
    src/qlib.c
    src/qlib_cfg.c
    src/qlib_cmd_proc.c
    src/qlib_common.c
    src/qlib_crypto.c
    src/qlib_key_mngr.c
    src/qlib_sec.c
    src/qlib_std.c
    utils/qlib_utils_crc.c
    utils/qlib_utils_digest.c
    utils/qlib_utils_lms.c
    samples/qlib_sample_secure_storage.c
    samples/qlib_sample_qconf.c
    samples/qlib_sample_qconf_config.c
    samples/remote/qlib_sample_server_main.c
    samples/remote/qlib_sample_server_platform.c
    samples/remote/qlib_sample_platform.c
)

# Add executable
add_executable(qlib_sample_server ${SOURCE_FILES})

# Link the pthread library
target_link_libraries(qlib_sample_server PRIVATE Threads::Threads)
