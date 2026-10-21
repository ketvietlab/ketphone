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
# SIP over TLS: Network.framework on Apple platforms, OpenSSL elsewhere. AUTO picks the platform's.
set(KETPHONE_TLS "AUTO" CACHE STRING "TLS implementation: AUTO, APPLE, OPENSSL or OFF")
set_property(CACHE KETPHONE_TLS PROPERTY STRINGS AUTO APPLE OPENSSL OFF)

add_library(ketphone_warnings INTERFACE)
target_compile_options(ketphone_warnings INTERFACE
  -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wnon-virtual-dtor -Wold-style-cast
  $<$<BOOL:${KETPHONE_WERROR}>:-Werror>)

if(KETPHONE_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL 1.1.1 COMPONENTS SSL Crypto)

set(ketphone_tls "${KETPHONE_TLS}")
if(ketphone_tls STREQUAL "AUTO")
  if(APPLE)
    set(ketphone_tls APPLE)
  elseif(OpenSSL_FOUND)
    set(ketphone_tls OPENSSL)
  else()
    set(ketphone_tls OFF)
  endif()
endif()
if(ketphone_tls STREQUAL "APPLE" AND NOT APPLE)
  message(FATAL_ERROR "KETPHONE_TLS=APPLE needs an Apple platform")
endif()
if(ketphone_tls STREQUAL "OPENSSL" AND NOT OpenSSL_FOUND)
  message(FATAL_ERROR "KETPHONE_TLS=OPENSSL needs OpenSSL (set OPENSSL_ROOT_DIR)")
endif()
message(STATUS "ketphone: TLS through ${ketphone_tls}")

# libsrtp (BSD-3-Clause), the subset for AES_CM_128_HMAC_SHA1_80 with its built-in crypto. Its
# objects go into libketphone.a, so callers link one library.
set(srtp_root ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsrtp)
add_library(ketphone_srtp OBJECT
  ${srtp_root}/srtp/srtp.c
  ${srtp_root}/crypto/cipher/aes.c
  ${srtp_root}/crypto/cipher/aes_icm.c
  ${srtp_root}/crypto/cipher/cipher.c
  ${srtp_root}/crypto/cipher/cipher_test_cases.c
  ${srtp_root}/crypto/cipher/null_cipher.c
  ${srtp_root}/crypto/hash/auth.c
  ${srtp_root}/crypto/hash/auth_test_cases.c
  ${srtp_root}/crypto/hash/hmac.c
  ${srtp_root}/crypto/hash/null_auth.c
  ${srtp_root}/crypto/hash/sha1.c
  ${srtp_root}/crypto/kernel/alloc.c
  ${srtp_root}/crypto/kernel/crypto_kernel.c
  ${srtp_root}/crypto/kernel/err.c
  ${srtp_root}/crypto/kernel/key.c
  ${srtp_root}/crypto/math/datatypes.c
  ${srtp_root}/crypto/replay/rdb.c
  ${srtp_root}/crypto/replay/rdbx.c
)
target_include_directories(ketphone_srtp
  PUBLIC ${srtp_root}/include ${srtp_root}/crypto/include
  PRIVATE ${srtp_root}/config)
target_compile_definitions(ketphone_srtp PRIVATE HAVE_CONFIG_H)
set_target_properties(ketphone_srtp PROPERTIES POSITION_INDEPENDENT_CODE ON C_STANDARD 99)
# Third-party code builds with its own warnings, never as errors.
target_compile_options(ketphone_srtp PRIVATE -w)

# The core is a static library: the iOS build links it into the app through an XCFramework, and
# the C header in include/ is the only surface callers see.
add_library(ketphone STATIC
  src/core/engine.cpp
  src/core/user_agent.cpp
  src/media/g711.cpp
  src/media/jitter_buffer.cpp
  src/media/media_session.cpp
  src/media/rtp.cpp
  src/media/srtp.cpp
  src/net/pem.cpp
  src/net/tls_apple.cpp
  src/net/tls_openssl.cpp
  src/net/udp_socket.cpp
  src/sip/base64.cpp
  src/sip/digest.cpp
  src/sip/md5.cpp
  src/sip/message.cpp
  src/sip/random.cpp
  src/sip/sdp.cpp
  src/sip/stream_framer.cpp
  $<TARGET_OBJECTS:ketphone_srtp>
)
target_include_directories(ketphone
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(ketphone PRIVATE $<TARGET_PROPERTY:ketphone_srtp,INTERFACE_INCLUDE_DIRECTORIES>)
target_link_libraries(ketphone PRIVATE ketphone_warnings Threads::Threads)
target_compile_definitions(ketphone PRIVATE KETPHONE_VERSION="${PROJECT_VERSION}")
if(ketphone_tls STREQUAL "APPLE")
  target_compile_definitions(ketphone PRIVATE KETPHONE_TLS_APPLE=1)
  target_link_libraries(ketphone PUBLIC "-framework Network" "-framework Security" "-framework CoreFoundation")
elseif(ketphone_tls STREQUAL "OPENSSL")
  target_compile_definitions(ketphone PRIVATE KETPHONE_TLS_OPENSSL=1)
  target_link_libraries(ketphone PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

if(KETPHONE_BUILD_TOOLS)
  add_executable(ketphone-poc tools/ketphone-poc/main.cpp)
  target_link_libraries(ketphone-poc PRIVATE ketphone ketphone_warnings Threads::Threads)
endif()

if(KETPHONE_BUILD_TESTS)
  enable_testing()
  add_executable(ketphone-tests
    tests/main.cpp
    tests/c_api_test.cpp
    tests/base64_test.cpp
    tests/digest_test.cpp
    tests/g711_test.cpp
    tests/jitter_buffer_test.cpp
    tests/message_test.cpp
    tests/network_simulation_test.cpp
    tests/ipv6_test.cpp
    tests/rtp_test.cpp
    tests/sdp_test.cpp
    tests/spsc_ring_test.cpp
    tests/srtp_test.cpp
    tests/stream_framer_test.cpp
    tests/tls_test.cpp
    tests/user_agent_test.cpp
  )
  target_include_directories(ketphone-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
    $<TARGET_PROPERTY:ketphone_srtp,INTERFACE_INCLUDE_DIRECTORIES>)
  target_link_libraries(ketphone-tests PRIVATE ketphone ketphone_warnings Threads::Threads)
  # The TLS tests play the server with OpenSSL, whichever implementation the client uses.
  if(OpenSSL_FOUND AND NOT ketphone_tls STREQUAL "OFF")
    target_sources(ketphone-tests PRIVATE tests/tls_server.cpp)
    target_compile_definitions(ketphone-tests PRIVATE KETPHONE_TEST_TLS=1)
    target_link_libraries(ketphone-tests PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  endif()
  add_test(NAME unit COMMAND ketphone-tests)
endif()
