#include "secure_random.h"
#include <string.h>
#include <limits.h>
#if defined(_WIN32)
  #include <windows.h>
  #include <bcrypt.h>
#elif defined(SECR2R_STM32)
  /* Implement this function in board-specific code using a reviewed CSPRNG
     and a real entropy source. Do not substitute an unseeded PRNG. */
  extern int secr2r_stm32_random_bytes(uint8_t *out, size_t length);
#elif defined(__linux__)
  #include <errno.h>
  #include <sys/random.h>
  #include <fcntl.h>
  #include <unistd.h>
#else
  #include <errno.h>
  #include <fcntl.h>
  #include <unistd.h>
#endif

int secr2r_random_bytes(uint8_t *out, size_t length) {
    if (out == NULL && length != 0u) return 0;
    if (length == 0u) return 1;
#if defined(_WIN32)
    if (length > (size_t)ULONG_MAX) return 0;
    return BCryptGenRandom(NULL, out, (ULONG)length,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#elif defined(SECR2R_STM32)
    return secr2r_stm32_random_bytes(out, length);
#elif defined(__linux__)
    size_t done = 0u;
    while (done < length) {
        ssize_t n = getrandom(out + done, length - done, 0);
        if (n > 0) { done += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    if (done == length) return 1;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    done = 0u;
    while (done < length) {
        ssize_t n = read(fd, out + done, length - done);
        if (n > 0) { done += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        close(fd); return 0;
    }
    close(fd); return 1;
#else
    /* POSIX fallback. STM32 needs a reviewed board-specific CSPRNG source. */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    size_t done = 0u;
    while (done < length) {
        ssize_t n = read(fd, out + done, length - done);
        if (n > 0) { done += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        close(fd); return 0;
    }
    close(fd); return 1;
#endif
}

int fe_gen_csprng(const uint8_t response[FE_INPUT_BITS],
                  fe_helper_t *helper, uint8_t secret[FE_SECRET_BYTES]) {
    uint8_t seed_bits[FE_SEED_BITS];
    uint8_t seed_bytes[(FE_SEED_BITS + 7u) / 8u];
    if (!response || !helper || !secret) return 0;
    memset(seed_bytes, 0, sizeof(seed_bytes));
    if (!secr2r_random_bytes(seed_bytes, sizeof(seed_bytes))) {
        memset(seed_bits, 0, sizeof(seed_bits));
        return 0;
    }
    for (size_t i = 0; i < FE_SEED_BITS; ++i)
        seed_bits[i] = (uint8_t)((seed_bytes[i / 8u] >> (7u - (i % 8u))) & 1u);
    int ok = fe_gen(response, seed_bits, helper, secret);
    memset(seed_bits, 0, sizeof(seed_bits));
    memset(seed_bytes, 0, sizeof(seed_bytes));
    return ok;
}
