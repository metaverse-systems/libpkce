# Using libpkce with the New Header Structure

After installing the libpkce-dev package, headers are now located in `/usr/include/libpkce/`.

## Example Usage

### Including Headers

```cpp
#include <libpkce/generate_code_verifier.hpp>
#include <libpkce/generate_code_challenge.hpp>
#include <libpkce/CallbackServer.hpp>
#include <libpkce/exchange_token.hpp>
```

### Compiling with pkg-config

```bash
g++ -o myapp myapp.cpp $(pkg-config --cflags --libs libpkce)
```

### Manual Compilation

```bash
g++ -o myapp myapp.cpp -I/usr/include -llibpkce -lssl -lcrypto
```

The headers are now properly namespaced under the `libpkce/` directory to avoid conflicts with other libraries.
