cmake_minimum_required(VERSION 3.16)
project(cryptnox_der_fuzz CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# fuzz_der: single-TU harness that includes CW_SecureChannel.cpp and
# CW_Utils.cpp directly, so only the SDK and uECC header directories
# are needed on the include path.
add_executable(fuzz_der fuzz_der.cpp)

target_include_directories(fuzz_der PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..                              # cryptnox-sdk-cpp headers
    ${CMAKE_CURRENT_SOURCE_DIR}/../../components/uECC/include  # uECC.h shim
)

target_compile_definitions(fuzz_der PRIVATE
    CW_FUZZ_BUILD=1
    CW_DEBUG_LOGGING=0
)

target_compile_options(fuzz_der PRIVATE
    -fsanitize=fuzzer,address
    -g
    -O1
    -Wall
    -Wno-unused-function
)

target_link_options(fuzz_der PRIVATE
    -fsanitize=fuzzer,address
)
