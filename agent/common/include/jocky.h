#ifndef JOCKY_H
#define JOCKY_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#ifdef JOCKY_EXPORTS
#define JOCKY_API __declspec(dllexport)
#else
#define JOCKY_API __declspec(dllimport)
#endif
#else
#define JOCKY_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Verify an Ed25519 consent token.
 *
 * @param token_bytes  JSON payload of the consent token
 * @param token_len    Length of token_bytes
 * @param pubkey_bytes 32-byte Ed25519 public key
 * @param pubkey_len   Length of pubkey_bytes (must be 32)
 * @return 0 on success, non-zero on error.
 */
JOCKY_API int32_t jocky_consent_token_verify(
    const uint8_t* token_bytes,
    size_t token_len,
    const uint8_t* pubkey_bytes,
    size_t pubkey_len
);

/**
 * No-op placeholder for token freeing (if a token handle were returned).
 */
JOCKY_API void jocky_consent_token_free(void);

/**
 * Verify a .jkm container signature.
 *
 * @param jkm_bytes    Raw bytes of the .jkm file
 * @param jkm_len      Length of jkm_bytes
 * @param pubkey_bytes 32-byte Ed25519 public key
 * @param pubkey_len   Length of pubkey_bytes (must be 32)
 * @return 0 on success, non-zero on error.
 */
JOCKY_API int32_t jocky_jkm_verify(
    const uint8_t* jkm_bytes,
    size_t jkm_len,
    const uint8_t* pubkey_bytes,
    size_t pubkey_len
);

/**
 * Free a string allocated by the Rust library.
 *
 * @param ptr String pointer returned by a JOCKY API
 */
JOCKY_API void jocky_free_string(char* ptr);

/**
 * Get the last error message from the thread-local storage.
 * The returned string must be freed using jocky_free_string().
 *
 * @return Null-terminated string or NULL if no error occurred.
 */
JOCKY_API char* jocky_last_error(void);

#ifdef __cplusplus
}
#endif

#endif // JOCKY_H
