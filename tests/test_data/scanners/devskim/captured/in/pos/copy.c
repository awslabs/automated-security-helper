#include <string.h>

void copy_name(char *dst, const char *src) {
    strcpy(dst, src);
}

size_t name_length(const char *name) {
    return strlen(name);
}
