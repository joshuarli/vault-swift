#ifndef VAULT_C_SYSTEM_H
#define VAULT_C_SYSTEM_H

#include <crt_externs.h>
#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

int32_t vault_keychain_set(
    const char *name,
    const uint8_t *value,
    size_t value_length
);
int32_t vault_keychain_get(
    const char *name,
    uint8_t **value,
    size_t *value_length
);
int32_t vault_keychain_delete(const char *name);
int32_t vault_keychain_list(char ***names, size_t *count);
int32_t vault_keychain_purge(size_t *count);
char *vault_keychain_status_message(int32_t status);
void vault_keychain_free(void *pointer);

#endif
