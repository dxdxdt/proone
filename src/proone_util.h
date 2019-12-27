#if 0
bool proone_strendsw (const char *str, const char *w) {
    const size_t len_str = strlen(str);
    const size_t len_w = strlen(w);

    if (len_str < len_w) {
        return false;
    }
    return strcmp(str + (len_str - len_w), w) == 0;
}
#endif
