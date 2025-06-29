ACLOCAL_AMFLAGS=-I m4
lib_LTLIBRARIES = libpkce.la
bin_PROGRAMS = pkce

# Install headers in libpkce subdirectory
libpkceincludedir = $(includedir)/libpkce
libpkceinclude_HEADERS = ../include/libpkce/generate_code_verifier.hpp \
    ../include/libpkce/generate_code_challenge.hpp \
    ../include/libpkce/exchange_token.hpp \
    ../include/libpkce/CallbackServer.hpp \
    ../include/libpkce/json.hpp \
    ../include/libpkce/token_utils.hpp

libpkce_la_SOURCES = generate_code_verifier.cpp generate_code_challenge.cpp CallbackServer.cpp exchange_token.cpp token_utils.cpp
libpkce_la_LIBADD = ${OPENSSL_LIBS} ${SOCKET_LIBS}
libpkce_la_CXXFLAGS = -std=c++20 ${OPENSSL_CFLAGS} -I../include

pkce_SOURCES = main.cpp
pkce_LDADD = libpkce.la ${OPENSSL_LIBS} ${SOCKET_LIBS}
pkce_CXXFLAGS = -std=c++20 ${OPENSSL_CFLAGS} -I../include
pkce_LDFLAGS = -static-libgcc -static-libstdc++
