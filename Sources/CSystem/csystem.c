#include "CSystem.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// The executable does not use floating-point values. Satisfy Swift's
// compatibility-library force-load hook locally so the weak float runtime
// dylib is not added to this integer-only wrapper.
void vault_swift_builtin_float(void)
    __asm__("__swift_FORCE_LOAD_$_swift_Builtin_float");
void vault_swift_builtin_float(void) {}

static CFStringRef vault_string(const char *value) {
    return CFStringCreateWithCString(
        kCFAllocatorDefault,
        value,
        kCFStringEncodingUTF8
    );
}

static CFMutableDictionaryRef vault_dictionary(void) {
    return CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
}

static CFMutableDictionaryRef vault_query(const char *name) {
    CFStringRef account = vault_string(name);
    CFStringRef service = vault_string("dev.joshuarli.vault");
    if (account == NULL || service == NULL) {
        if (account != NULL) CFRelease(account);
        if (service != NULL) CFRelease(service);
        return NULL;
    }

    CFMutableDictionaryRef query = vault_dictionary();
    if (query == NULL) {
        CFRelease(account);
        CFRelease(service);
        return NULL;
    }
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, service);
    if (name[0] != '\0') {
        CFDictionarySetValue(query, kSecAttrAccount, account);
    }
    CFRelease(account);
    CFRelease(service);
    return query;
}

static CFMutableDictionaryRef vault_value_attributes(
    const uint8_t *value,
    size_t value_length
) {
    CFDataRef data = CFDataCreate(
        kCFAllocatorDefault,
        value,
        (CFIndex)value_length
    );
    if (data == NULL) return NULL;

    CFMutableDictionaryRef attributes = vault_dictionary();
    if (attributes == NULL) {
        CFRelease(data);
        return NULL;
    }
    CFDictionarySetValue(attributes, kSecValueData, data);
    CFRelease(data);
    return attributes;
}

OSStatus vault_keychain_set(
    const char *name,
    const uint8_t *value,
    size_t value_length
) {
    CFMutableDictionaryRef query = vault_query(name);
    CFMutableDictionaryRef update = vault_value_attributes(value, value_length);
    if (query == NULL || update == NULL) {
        if (query != NULL) CFRelease(query);
        if (update != NULL) CFRelease(update);
        return errSecParam;
    }

    OSStatus status = SecItemUpdate(query, update);
    CFRelease(query);
    CFRelease(update);
    if (status == errSecSuccess) return status;
    if (status != errSecItemNotFound) return status;

    CFMutableDictionaryRef attributes = vault_value_attributes(value, value_length);
    if (attributes == NULL) {
        return errSecParam;
    }
    CFDictionarySetValue(attributes, kSecClass, kSecClassGenericPassword);
    CFStringRef account = vault_string(name);
    CFStringRef service = vault_string("dev.joshuarli.vault");
    if (account == NULL || service == NULL) {
        if (account != NULL) CFRelease(account);
        if (service != NULL) CFRelease(service);
        CFRelease(attributes);
        return errSecParam;
    }
    CFDictionarySetValue(attributes, kSecAttrService, service);
    CFDictionarySetValue(attributes, kSecAttrAccount, account);
    CFRelease(account);
    CFRelease(service);
    status = SecItemAdd(attributes, NULL);
    CFRelease(attributes);
    return status;
}

OSStatus vault_keychain_get(
    const char *name,
    uint8_t **value,
    size_t *value_length
) {
    *value = NULL;
    *value_length = 0;
    CFMutableDictionaryRef query = vault_query(name);
    if (query == NULL) return errSecParam;
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status != errSecSuccess) return status;
    if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
        if (result != NULL) CFRelease(result);
        return errSecDecode;
    }

    CFDataRef data = (CFDataRef)result;
    CFIndex length = CFDataGetLength(data);
    if (length > 0) {
        uint8_t *copy = malloc((size_t)length);
        if (copy == NULL) {
            CFRelease(data);
            return errSecAllocate;
        }
        CFDataGetBytes(data, CFRangeMake(0, length), copy);
        *value = copy;
        *value_length = (size_t)length;
    }
    CFRelease(data);
    return errSecSuccess;
}

OSStatus vault_keychain_delete(const char *name) {
    CFMutableDictionaryRef query = vault_query(name);
    if (query == NULL) return errSecParam;
    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    return status;
}

static int vault_compare_names(const void *lhs, const void *rhs) {
    const char *const *left = lhs;
    const char *const *right = rhs;
    return strcmp(*left, *right);
}

OSStatus vault_keychain_list(char ***names, size_t *count) {
    *names = NULL;
    *count = 0;
    CFMutableDictionaryRef query = vault_query("");
    if (query == NULL) return errSecParam;
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status == errSecItemNotFound) return errSecSuccess;
    if (status != errSecSuccess) return status;
    if (result == NULL || CFGetTypeID(result) != CFArrayGetTypeID()) {
        if (result != NULL) CFRelease(result);
        return errSecDecode;
    }

    CFArrayRef items = (CFArrayRef)result;
    CFIndex item_count = CFArrayGetCount(items);
    char **result_names = calloc((size_t)item_count, sizeof(char *));
    if (result_names == NULL && item_count != 0) {
        CFRelease(items);
        return errSecAllocate;
    }
    size_t result_count = 0;
    for (CFIndex index = 0; index < item_count; index++) {
        CFDictionaryRef item = (CFDictionaryRef)CFArrayGetValueAtIndex(items, index);
        CFStringRef account = (CFStringRef)CFDictionaryGetValue(item, kSecAttrAccount);
        if (account == NULL || CFGetTypeID(account) != CFStringGetTypeID()) continue;
        CFIndex capacity = CFStringGetMaximumSizeForEncoding(
            CFStringGetLength(account),
            kCFStringEncodingUTF8
        ) + 1;
        char *name = malloc((size_t)capacity);
        if (name == NULL || !CFStringGetCString(
            account,
            name,
            capacity,
            kCFStringEncodingUTF8
        )) {
            free(name);
            for (size_t free_index = 0; free_index < result_count; free_index++) {
                free(result_names[free_index]);
            }
            free(result_names);
            CFRelease(items);
            return errSecDecode;
        }
        result_names[result_count++] = name;
    }
    CFRelease(items);
    qsort(result_names, result_count, sizeof(char *), vault_compare_names);
    *names = result_names;
    *count = result_count;
    return errSecSuccess;
}

OSStatus vault_keychain_purge(size_t *count) {
    char **names = NULL;
    size_t name_count = 0;
    OSStatus status = vault_keychain_list(&names, &name_count);
    if (status != errSecSuccess) return status;
    for (size_t index = 0; index < name_count; index++) {
        status = vault_keychain_delete(names[index]);
        free(names[index]);
        if (status != errSecSuccess) {
            for (size_t free_index = index + 1; free_index < name_count; free_index++) {
                free(names[free_index]);
            }
            free(names);
            return status;
        }
    }
    free(names);
    *count = name_count;
    return errSecSuccess;
}

char *vault_keychain_status_message(OSStatus status) {
    CFStringRef message = SecCopyErrorMessageString(status, NULL);
    if (message == NULL) return NULL;
    CFIndex capacity = CFStringGetMaximumSizeForEncoding(
        CFStringGetLength(message),
        kCFStringEncodingUTF8
    ) + 1;
    char *result = malloc((size_t)capacity);
    if (result == NULL || !CFStringGetCString(
        message,
        result,
        capacity,
        kCFStringEncodingUTF8
    )) {
        free(result);
        CFRelease(message);
        return NULL;
    }
    CFRelease(message);
    return result;
}

void vault_keychain_free(void *pointer) {
    free(pointer);
}
