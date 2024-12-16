cmake_minimum_required(VERSION 3.31.2)
project(my-first-pass-searcher)

#==========================
# 1.加载LLVM CONFIGURATION
#==========================
# 设置其为有效的LLVM安装地点
# 这里是设置LT_LLVM_INSTALL_DIR默认为"/usr"
# CACHE PATH是指允许用户自行修改该路径，并且覆盖CMake的缓存
# 比如可以利用-DLT_LLVM_INSTALL_DIR=/path/to/llvm
set(LT_LLVM_INSTALL_DIR "/usr" CACHE PATH "LLVM installation directory")

# 添加LLVMConfig.cmake到CMake 查询的路径
# LLVMConfig.cmake提供了LLVM安装的详细信息，例如库路径、头文件路径、版本信息
list(APPEND CMAKE_PERFIX_PATH "${LT_LLVM_INSTALL_DIR}/lib/cmake/llvm/")

# CONFIG表示要求使用LLVMConfig.cmake
find_package(LLVM CONFIG)

if("${LLVM_VERSION_MAJOR}" VERSION_LESS 18)
    message(FATAL_ERROR "Found LLVM ${LLVM_VERSION_MAJOR}, but need 18 or above")
endif()

# FnArgCnt 的头文件,添加到编译器-I搜索路径
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

#===========================
# 2.LLVM BUILD CONFIGURATION
#===========================

# 设置使用C++ 17标准
set(CMAKE_CXX_STANDARD 17 CACHE STRING "")

# LLVM 普遍在无RTTI下构建
if(NOT LLVM_ENABLE_RTTI)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}" -fno-rtti)
endif()

#================================
# 3. 添加目标
#================================


# 添加动态库，名字为FindCmpEq
add_library(FindSpecificStruct SHARED ./src/FindSpecificStruct.cpp)

target_link_libraries(FindSpecificStruct "$<$<PLATFORM_ID:Darwin>:-undefined dynamic_lookup>")

