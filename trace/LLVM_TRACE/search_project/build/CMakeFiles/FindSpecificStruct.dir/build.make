# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.31

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project/build

# Include any dependencies generated for this target.
include CMakeFiles/FindSpecificStruct.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/FindSpecificStruct.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/FindSpecificStruct.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/FindSpecificStruct.dir/flags.make

CMakeFiles/FindSpecificStruct.dir/codegen:
.PHONY : CMakeFiles/FindSpecificStruct.dir/codegen

CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.o: CMakeFiles/FindSpecificStruct.dir/flags.make
CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.o: /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project/src/FindSpecificStruct.cpp
CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.o: CMakeFiles/FindSpecificStruct.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.o -MF CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.o.d -o CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.o -c /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project/src/FindSpecificStruct.cpp

CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project/src/FindSpecificStruct.cpp > CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.i

CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project/src/FindSpecificStruct.cpp -o CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.s

# Object files for target FindSpecificStruct
FindSpecificStruct_OBJECTS = \
"CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.o"

# External object files for target FindSpecificStruct
FindSpecificStruct_EXTERNAL_OBJECTS =

libFindSpecificStruct.so: CMakeFiles/FindSpecificStruct.dir/src/FindSpecificStruct.cpp.o
libFindSpecificStruct.so: CMakeFiles/FindSpecificStruct.dir/build.make
libFindSpecificStruct.so: CMakeFiles/FindSpecificStruct.dir/compiler_depend.ts
libFindSpecificStruct.so: CMakeFiles/FindSpecificStruct.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared library libFindSpecificStruct.so"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/FindSpecificStruct.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/FindSpecificStruct.dir/build: libFindSpecificStruct.so
.PHONY : CMakeFiles/FindSpecificStruct.dir/build

CMakeFiles/FindSpecificStruct.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/FindSpecificStruct.dir/cmake_clean.cmake
.PHONY : CMakeFiles/FindSpecificStruct.dir/clean

CMakeFiles/FindSpecificStruct.dir/depend:
	cd /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project/build /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project/build /home/peiwithhao/repo/Hacker-University-of-peiwithhao/trace/LLVM_TRACE/search_project/build/CMakeFiles/FindSpecificStruct.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/FindSpecificStruct.dir/depend

