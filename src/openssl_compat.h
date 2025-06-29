#pragma once

// OpenSSL 3.0 compatibility for MinGW cross-compilation
// This header should be included before httplib.h to provide necessary macro definitions

#define CPPHTTPLIB_OPENSSL_SUPPORT

// For now, let's not redefine the function and see if we can get SSL_get1_peer_certificate to link
// The function exists in the library, so it might be a linking issue rather than a compatibility issue
