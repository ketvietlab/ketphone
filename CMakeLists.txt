cmake_minimum_required(VERSION 3.24)

project(ketphone VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(KETPHONE_WERROR "Treat compiler warnings as errors" OFF)
option(KETPHONE_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(KETPHONE_BUILD_TOOLS "Build the ketphone-poc command-line tool" ON)
option(KETPHONE_BUILD_TESTS "Build the unit tests" ON)

add_library(ketphone_warnings INTERFACE)
target_compile_options(ketphone_warnings INTERFACE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wnon-virtual-dtor -Wold-style-cast
  $<$<BOOL:${KETPHONE_WERROR}>:-Werror>)

if(KETPHONE_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(Threads REQUIRED)

# The core is a static library: the iOS build links it into the app through an XCFramework, and
# the C header in include/ is the only surface callers see.
add_library(ketphone STATIC
  src/core/engine.cpp
  src/core/user_agent.cpp
  src/media/g711.cpp
  src/media/jitter_buffer.cpp
  src/media/media_session.cpp
  src/media/rtp.cpp
  src/net/udp_socket.cpp
  src/sip/digest.cpp
  src/sip/md5.cpp
  src/sip/message.cpp
  src/sip/random.cpp
  src/sip/sdp.cpp
)
target_include_directories(ketphone
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(ketphone PRIVATE ketphone_warnings Threads::Threads)
target_compile_definitions(ketphone PRIVATE KETPHONE_VERSION="${PROJECT_VERSION}")

if(KETPHONE_BUILD_TOOLS)
  add_executable(ketphone-poc tools/ketphone-poc/main.cpp)
  target_link_libraries(ketphone-poc PRIVATE ketphone ketphone_warnings Threads::Threads)
endif()

if(KETPHONE_BUILD_TESTS)
  enable_testing()
  add_executable(ketphone-tests
    tests/main.cpp
    tests/c_api_test.cpp
    tests/digest_test.cpp
    tests/g711_test.cpp
    tests/jitter_buffer_test.cpp
    tests/message_test.cpp
    tests/rtp_test.cpp
    tests/sdp_test.cpp
    tests/spsc_ring_test.cpp
    tests/user_agent_test.cpp
  )
  target_include_directories(ketphone-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(ketphone-tests PRIVATE ketphone ketphone_warnings Threads::Threads)
  add_test(NAME unit COMMAND ketphone-tests)
endif()
