ACLOCAL_AMFLAGS=-I m4
lib_LTLIBRARIES = libpkce.la
bin_PROGRAMS = pkce

# Install headers in libpkce subdirectory
libpkceincludedir = $(includedir)/libpkce
libpkceinclude_HEADERS = generate_code_verifier.hpp generate_code_challenge.hpp CallbackServer.hpp exchange_token.hpp

libpkce_la_SOURCES = generate_code_verifier.cpp generate_code_challenge.cpp CallbackServer.cpp exchange_token.cpp
libpkce_la_LIBADD = ${OPENSSL_LIBS} ${SOCKET_LIBS}
libpkce_la_CXXFLAGS = -std=c++20 ${OPENSSL_CFLAGS}

pkce_SOURCES = main.cpp
pkce_LDADD = libpkce.la ${OPENSSL_LIBS} ${SOCKET_LIBS}
pkce_CXXFLAGS = -std=c++20 ${OPENSSL_CFLAGS}
pkce_LDFLAGS = -static-libgcc -static-libstdc++
