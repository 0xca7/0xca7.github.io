---
title: "Bggp5"
date: 2024-06-23T13:30:41+02:00
draft: false
---

This year's Binary Golf Grand Prix (BGGP5) states the following goal:

*Create the smallest file that downloads [LINK] text file and displays its contents.*

Instead of an actual compiled program, I thought I'd go for something a little bit more obscure. A Downloader using the build system `cmake`!

I'm using Linux, so to install the build system run:

```
sudo apt install cmake
```

This is the version I am running:

```
$ cmake --version
cmake version 3.28.3
```

... and here's the downloader:

```
cmake_minimum_required(VERSION 3.28)
include(FetchContent)
FetchContent_Declare(b URL https://binary.golf/5/5 DOWNLOAD_NO_EXTRACT TRUE)
FetchContent_MakeAvailable(b)
execute_process (COMMAND bash -c "cat _deps/b-subbuild/b-populate-prefix/src/5" OUTPUT_VARIABLE o)
MESSAGE(INFO ${o})
```

All this does is fetch the downloader from the URL specified in the challenge and then execute the `cat` bash command to print the downloaded file's content to stdout. You can use this script for testing my entry:

```bash
#!/bin/bash

rm -rf build
mkdir build ; cd build
cmake ..
```

Running the shell script, which in turn just sets up a directory and runs cmake, yields the following output:

```
CMake Warning (dev) in CMakeLists.txt:
  No project() command is present.  The top-level CMakeLists.txt file must
  contain a literal, direct call to the project() command.  Add a line of
  code such as

    project(ProjectName)

  near the top of the file, but after cmake_minimum_required().

  CMake is pretending there is a "project(Project)" command on the first
  line.
This warning is for project developers.  Use -Wno-dev to suppress it.

CMake Warning (dev) in CMakeLists.txt:
  cmake_minimum_required() should be called prior to this top-level project()
  call.  Please see the cmake-commands(7) manual for usage documentation of
  both commands.
This warning is for project developers.  Use -Wno-dev to suppress it.

-- The C compiler identification is GNU 13.2.0
-- The CXX compiler identification is GNU 13.2.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
INFOAnother #BGGP5 download!! @binarygolf https://binary.golf

-- Configuring done (1.1s)
-- Generating done (0.0s)
-- Build files have been written to: /home/nmt/work/hacking/bggp/cmake-downloader/build
```

Note that the file's contents are printed in the line starting with `INFO`.

Here's the SHA256 of my entry, the CMakeLists.txt has `283` bytes.

```
SHA256: 27a46761d80b58565970b941d2f0e8f26626e4b3756705a0d121bb8271c0a0f2  
```

### 0xca7
