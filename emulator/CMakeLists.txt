cmake_minimum_required(VERSION 3.27)
project(emulator)
include(FetchContent)

set(CMAKE_CXX_STANDARD 17)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

FetchContent_Declare(httplib SYSTEM
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib
        GIT_TAG 5c00bbf36ba8ff47b4fb97712fc38cb2884e5b98 # v0.14.1
        GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(httplib)

if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT")
endif ()

add_executable(emulator src/main.cpp)
target_link_libraries(emulator PRIVATE httplib OpenSSL::SSL)
