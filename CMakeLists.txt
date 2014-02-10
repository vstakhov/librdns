PROJECT(librdns C)

SET(RSPAMD_VERSION_MAJOR 0)
SET(RSPAMD_VERSION_MINOR 0)
SET(RSPAMD_VERSION_PATCH 0)

CMAKE_MINIMUM_REQUIRED(VERSION 2.6.0 FATAL_ERROR)

INCLUDE(CheckFunctionExists)
INCLUDE(CheckSymbolExists)

CHECK_SYMBOL_EXISTS(IPV6_V6ONLY "sys/socket.h;netinet/in.h" HAVE_IPV6_V6ONLY)

CHECK_SYMBOL_EXISTS(getaddrinfo "sys/types.h;sys/socket.h;netdb.h" HAVE_GETADDRINFO)
IF(NOT HAVE_GETADDRINFO)
	MESSAGE(FATAL_ERROR "Your system does not support getaddrinfo call, please consider upgrading it to run librdns")
ENDIF(NOT HAVE_GETADDRINFO)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

SET(LIBRDNSSRC			src/dns_util.c
						src/dns.c
						src/punycode.c
						src/dns_curve.c)

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/src" 
					"${CMAKE_SOURCE_DIR}/include" 
					"${CMAKE_BINARY_DIR}/src"
					"${CMAKE_BINARY_DIR}/include"  
					"${CMAKE_SOURCE_DIR}/contrib/uthash"
					"${CMAKE_SOURCE_DIR}/contrib/libottery")

ADD_SUBDIRECTORY(contrib/libottery)
ADD_SUBDIRECTORY(test)

ADD_LIBRARY(rdns STATIC ${LIBRDNSSRC})
TARGET_LINK_LIBRARIES(rdns rdns-ottery)