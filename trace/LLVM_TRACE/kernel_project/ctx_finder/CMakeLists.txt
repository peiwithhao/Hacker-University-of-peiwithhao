cmake_minimum_required(VERSION 3.31.2)
project(my-ctx-finder)


set(LT_LLVM_INSTALL_DIR "/home/peiwithhao/Desktop/llvm-19/install/" CACHE PATH "LLVM installation directory")
set(PROJECT_INCLUDE "./include/" CACHE PATH "Project include directory")
set(LT_LLVM_INCLUDE_DIR "${LT_LLVM_INSTALL_DIR}/include/")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)



list(APPEND CMAKE_PERFIX_PATH "${LT_LLVM_INSTALL_DIR}/lib/cmake/llvm/")
find_package(LLVM CONFIG)

if("${LLVM_VERSION_MAJOR}" VERSION_LESS 18)
    message(FATAL_ERROR "Found LLVM ${LLVM_VERSION_MAJOR}, but need 18 or above")
endif()


## 添加头文件
include_directories(${LT_LLVM_INCLUDE_DIR})
include_directories(${PROJECT_INCLUDE})



# 设置使用C++ 17标准
set(CMAKE_CXX_STANDARD 17 CACHE STRING "")

# LLVM 普遍在无RTTI下构建
if(NOT LLVM_ENABLE_RTTI)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}" -fno-rtti)
endif()


add_library(ctxFinder SHARED src/ctxFinder.cpp)

# Allow undefined symbols in shared objects on Darwin (this is the default
# behaviour on Linux)
target_link_libraries(ctxFinder
  "$<$<PLATFORM_ID:Darwin>:-undefined dynamic_lookup>")
