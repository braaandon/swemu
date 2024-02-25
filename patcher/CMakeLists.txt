cmake_minimum_required(VERSION 3.27)
project(patcher)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(minhook)

add_library(patcher SHARED src/library.cpp)
target_include_directories(patcher PRIVATE minhook/include)
target_link_libraries(patcher PRIVATE minhook)

