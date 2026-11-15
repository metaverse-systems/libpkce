AM_CXXFLAGS = -std=c++20 -I$(top_srcdir)/include ${OPENSSL_CFLAGS} -pthread
LDADD = ../src/libpkce.la $(OPENSSL_LIBS) $(SOCKET_LIBS) -lpthread

check_PROGRAMS = callback_silent_test callback_two_write_test callback_stop_test token_response_default_test

callback_silent_test_SOURCES = callback_silent_test.cpp
callback_two_write_test_SOURCES = callback_two_write_test.cpp
callback_stop_test_SOURCES = callback_stop_test.cpp
token_response_default_test_SOURCES = token_response_default_test.cpp

EXTRA_DIST = loopback.hpp

TESTS = $(check_PROGRAMS)
