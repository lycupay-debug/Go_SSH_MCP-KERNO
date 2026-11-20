#include <json-c/json.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <sys/extattr.h>
#include <sha256.h>
#include <stdint.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <ftw.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define INPUT_LIMIT (32 * 1024 * 1024)
#define OUTPUT_LIMIT (1024 * 1024)
#define SHELL_STDOUT_LIMIT 120000
#define SHELL_STDERR_LIMIT 40000
#define FILE_LIMIT (4 * 1024 * 1024)
#define DIRECTORY_JSON_LIMIT (15 * 1024 * 1024)

#define TEMP_CLEANUP_PATH_SIZE (PATH_MAX + 32)

static volatile sig_atomic_t temp_cleanup_active = 0;
static char temp_cleanup_path[TEMP_CLEANUP_PATH_SIZE];

static void atomic_temp_signal_handler(int signal_number) {
    if (temp_cleanup_active) (void)unlink(temp_cleanup_path);
    _exit(128 + signal_number);
}

static int install_atomic_temp_signal_handlers(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = atomic_temp_signal_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0) return -1;
    if (sigaction(SIGINT, &action, NULL) != 0) return -1;
    return 0;
}

static int register_atomic_temp_cleanup(const char *path) {
    size_t length = strlen(path);
    if (length >= sizeof(temp_cleanup_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(temp_cleanup_path, path, length + 1);
    temp_cleanup_active = 1;
    return 0;
}

static void clear_atomic_temp_cleanup(void) {
    sigset_t blocked, previous;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGINT);
    (void)sigprocmask(SIG_BLOCK, &blocked, &previous);
    temp_cleanup_active = 0;
    temp_cleanup_path[0] = '\0';
    (void)sigprocmask(SIG_SETMASK, &previous, NULL);
}

static const char *jstr(struct json_object *o, const char *key) {
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v) || !v ||
        json_object_get_type(v) != json_type_string) return NULL;
    return json_object_get_string(v);
}
static const char *jpath(struct json_object *o, const char *key) {
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v) || !v || json_object_get_type(v) != json_type_string) return NULL;
    const char *value = json_object_get_string(v);
    if (!value || strlen(value) != (size_t)json_object_get_string_len(v)) return NULL;
    return value;
}
static int jint(struct json_object *o, const char *key, int fallback) {
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v) || !v ||
        json_object_get_type(v) != json_type_int) return fallback;
    return json_object_get_int(v);
}
static int jbool(struct json_object *o, const char *key, int fallback) {
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v) || !v ||
        json_object_get_type(v) != json_type_boolean) return fallback;
    return json_object_get_boolean(v);
}
static void set_error(struct json_object *out, const char *code, const char *message) {
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    struct json_object *e = json_object_new_object();
    json_object_object_add(e, "code", json_object_new_string(code));
    json_object_object_add(e, "message", json_object_new_string(message));
    json_object_object_add(out, "error", e);
}
static void set_ok(struct json_object *out, struct json_object *result) {
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "result", result ? result : json_object_new_object());
}
static struct json_object *result_object(void) { return json_object_new_object(); }
static int list_directory(const char *path, struct json_object *out) {
    DIR *dir = opendir(path);
    if (!dir) { set_error(out, "DIRECTORY_OPEN_FAILED", strerror(errno)); return -1; }
    struct json_object *items = json_object_new_array();
    if (!items) { closedir(dir); set_error(out, "OUT_OF_MEMORY", "Allocation failed."); return -1; }
    struct dirent *entry;
    size_t count = 0;
    size_t encoded_size = 0;
    int read_error = 0;
    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) { read_error = errno; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        size_t plen = strlen(path), nlen = strlen(entry->d_name);
        int slash = plen > 0 && path[plen - 1] != '/';
        char *full = malloc(plen + (size_t)slash + nlen + 1);
        if (!full) { json_object_put(items); closedir(dir); set_error(out, "OUT_OF_MEMORY", "Allocation failed."); return -1; }
        memcpy(full, path, plen);
        size_t off = plen;
        if (slash) full[off++] = '/';
        memcpy(full + off, entry->d_name, nlen + 1);
        struct stat st;
        if (lstat(full, &st) != 0) { free(full); continue; }
        const char *type = S_ISLNK(st.st_mode) ? "symlink" : S_ISDIR(st.st_mode) ? "directory" : "file";
        struct json_object *item = json_object_new_object();
        json_object_object_add(item, "name", json_object_new_string(entry->d_name));
        json_object_object_add(item, "path", json_object_new_string(full));
        json_object_object_add(item, "type", json_object_new_string(type));
        json_object_object_add(item, "size", json_object_new_int64((int64_t)st.st_size));
        char modebuf[8];
        snprintf(modebuf, sizeof(modebuf), "0o%o", (unsigned int)(st.st_mode & 07777));
        json_object_object_add(item, "mode", json_object_new_string(modebuf));
        json_object_object_add(item, "owner_uid", json_object_new_int64((int64_t)st.st_uid));
        json_object_object_add(item, "group_gid", json_object_new_int64((int64_t)st.st_gid));
        const char *item_json = json_object_to_json_string_ext(item, JSON_C_TO_STRING_PLAIN);
        size_t item_size = item_json ? strlen(item_json) : DIRECTORY_JSON_LIMIT + 1;
        size_t separator_size = count > 0 ? 1 : 0;
        if (encoded_size > DIRECTORY_JSON_LIMIT || separator_size > DIRECTORY_JSON_LIMIT - encoded_size || item_size > DIRECTORY_JSON_LIMIT - encoded_size - separator_size) {
            json_object_put(item);
            free(full);
            json_object_put(items);
            closedir(dir);
            set_error(out, "DIRECTORY_OUTPUT_LIMIT", "Directory listing exceeds the 15 MiB serialized item budget.");
            return -1;
        }
        encoded_size += separator_size + item_size;
        json_object_array_add(items, item);
        free(full);
        count++;
    }
    closedir(dir);
    if (read_error != 0) { json_object_put(items); set_error(out, "DIRECTORY_READ_FAILED", strerror(read_error)); return -1; }
    struct json_object *res = result_object();
    json_object_object_add(res, "path", json_object_new_string(path));
    json_object_object_add(res, "entries", items);
    json_object_object_add(res, "count", json_object_new_int64((int64_t)count));
    set_ok(out, res);
    return 0;
}

static int read_file(const char *path, size_t max_bytes, struct json_object *out) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { set_error(out, "FILE_OPEN_FAILED", strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd); set_error(out, "NOT_REGULAR_FILE", "Only regular files are readable by file.read."); return -1;
    }
    if (st.st_size < 0 || (uintmax_t)st.st_size > max_bytes) {
        close(fd); set_error(out, "FILE_TOO_LARGE", "File exceeds max_bytes."); return -1;
    }
    size_t cap = (size_t)st.st_size + 1;
    char *buf = calloc(cap ? cap : 1, 1);
    if (!buf) { close(fd); set_error(out, "OUT_OF_MEMORY", "Allocation failed."); return -1; }
    size_t n = 0;
    while (n < cap - 1) {
        ssize_t r = read(fd, buf + n, cap - 1 - n);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) { free(buf); close(fd); set_error(out, "FILE_READ_FAILED", strerror(errno)); return -1; }
        if (r == 0) break;
        n += (size_t)r;
    }
    close(fd);
    struct json_object *res = result_object();
    json_object_object_add(res, "path", json_object_new_string(path));
    json_object_object_add(res, "content", json_object_new_string_len(buf, (int)n));
    json_object_object_add(res, "bytes_read", json_object_new_int64((int64_t)n));
    set_ok(out, res);
    free(buf);
    return 0;
}

static int read_file_limited(const char *path, size_t max_bytes, struct json_object *out) {
    int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0){set_error(out,"FILE_OPEN_FAILED",strerror(errno));return -1;}
    struct stat st;if(fstat(fd,&st)!=0||!S_ISREG(st.st_mode)){close(fd);set_error(out,"NOT_REGULAR_FILE","Only regular files are readable.");return -1;}
    char *buf=calloc(max_bytes+2,1);if(!buf){close(fd);set_error(out,"OUT_OF_MEMORY","Allocation failed.");return -1;}
    size_t n=0;while(n<max_bytes+1){ssize_t r=read(fd,buf+n,max_bytes+1-n);if(r<0&&errno==EINTR)continue;if(r<0){free(buf);close(fd);set_error(out,"FILE_READ_FAILED",strerror(errno));return -1;}if(r==0)break;n+=(size_t)r;}close(fd);
    int truncated=n>max_bytes;if(truncated)n=max_bytes;
    struct json_object *res=result_object();json_object_object_add(res,"path",json_object_new_string(path));json_object_object_add(res,"content",json_object_new_string_len(buf,(int)n));json_object_object_add(res,"bytes_read",json_object_new_int64((int64_t)n));json_object_object_add(res,"truncated",json_object_new_boolean(truncated));set_ok(out,res);free(buf);return 0;
}

static int mkdir_parents(const char *path) {
    char *copy = strdup(path);
    if (!copy) return -1;
    for (char *p = copy + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(copy, 0755) != 0 && errno != EEXIST) { free(copy); return -1; }
            *p = '/';
        }
    }
    free(copy);
    return 0;
}
static int write_text_file(const char *path, const char *data, size_t len, int create_parents, struct json_object *out) {
    if (create_parents && mkdir_parents(path) != 0) { set_error(out, "MKDIR_FAILED", strerror(errno)); return -1; }
    struct stat st; int previously_existed = (stat(path, &st) == 0);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) { set_error(out, "FILE_WRITE_FAILED", strerror(errno)); return -1; }
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { int saved = errno ? errno : EIO; close(fd); errno = saved; set_error(out, "FILE_WRITE_FAILED", strerror(errno)); return -1; }
        off += (size_t)w;
    }
    if (close(fd) != 0) { set_error(out, "FILE_WRITE_FAILED", strerror(errno)); return -1; }
    struct json_object *res = result_object();
    size_t characters_written = 0, i = 0;
    const uint64_t high_bits = UINT64_C(0x8080808080808080);
    for (; i + sizeof(uint64_t) <= len; i += sizeof(uint64_t)) {
        uint64_t word; memcpy(&word, data + i, sizeof(word));
        if ((word & high_bits) == 0) { characters_written += sizeof(word); continue; }
        for (size_t j = 0; j < sizeof(word); j++) if (((unsigned char)data[i + j] & 0xC0) != 0x80) characters_written++;
    }
    for (; i < len; i++) if (((unsigned char)data[i] & 0xC0) != 0x80) characters_written++;
    json_object_object_add(res, "path", json_object_new_string(path));
    json_object_object_add(res, "bytes_written", json_object_new_int64((int64_t)len));
    json_object_object_add(res, "characters_written", json_object_new_int64((int64_t)characters_written));
    json_object_object_add(res, "previously_existed", json_object_new_boolean(previously_existed));
    set_ok(out, res);
    return 0;
}

static int atomic_write(const char *path, const char *data, size_t len, int create_parents, struct json_object *out) {
    if (create_parents && mkdir_parents(path) != 0) { set_error(out, "MKDIR_FAILED", strerror(errno)); return -1; }
    struct stat oldst;
    int previously_existed = 0;
    mode_t mode = 0644;
    if (lstat(path, &oldst) == 0) {
        previously_existed = 1;
        if (!S_ISREG(oldst.st_mode)) { set_error(out, "NOT_REGULAR_FILE", "Refusing to replace a non-regular file."); return -1; }
        mode = oldst.st_mode & 07777;
    } else if (errno != ENOENT) { set_error(out, "FILE_STAT_FAILED", strerror(errno)); return -1; }
    char *tmp = malloc(strlen(path) + 16);
    if (!tmp) { set_error(out, "OUT_OF_MEMORY", "Allocation failed."); return -1; }
    sprintf(tmp, "%s.tmp.XXXXXX", path);
    int fd = mkstemp(tmp);
    if (fd < 0) { free(tmp); set_error(out, "TEMP_CREATE_FAILED", strerror(errno)); return -1; }
    if (register_atomic_temp_cleanup(tmp) != 0) {
        int saved = errno; close(fd); unlink(tmp); free(tmp); errno = saved;
        set_error(out, "TEMP_PATH_TOO_LONG", strerror(errno));
        return -1;
    }
    int ok = 1;
    if (fchmod(fd, mode) != 0) ok = 0;
    size_t off = 0;
    while (ok && off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { ok = 0; break; }
        off += (size_t)w;
    }
    if (ok && fsync(fd) != 0) ok = 0;
    int saved = errno;
    if (close(fd) != 0 && ok) { ok = 0; saved = errno; }
    if (ok && rename(tmp, path) != 0) { ok = 0; saved = errno; }
    if (ok) clear_atomic_temp_cleanup();
    if (!ok) {
        unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); errno = saved;
        set_error(out, "ATOMIC_WRITE_FAILED", strerror(errno)); return -1;
    }
    free(tmp);
    struct json_object *res = result_object();
    json_object_object_add(res, "path", json_object_new_string(path));
    json_object_object_add(res, "bytes_written", json_object_new_int64((int64_t)len));
    json_object_object_add(res, "previously_existed", json_object_new_boolean(previously_existed));
    json_object_object_add(res, "atomic", json_object_new_boolean(1));
    set_ok(out, res);
    return 0;
}

/*
 * Resolve the destination of an atomic replacement. Existing symlinks are
 * followed to their final target; a dangling symlink is rejected. For a new
 * file, canonicalize its parent directory and retain the requested basename.
 */
static char *resolve_atomic_target(const char *path, struct stat *target_st, int *exists, struct json_object *out) {
    struct stat lst;
    if (lstat(path, &lst) == 0) {
        char *resolved = realpath(path, NULL);
        if (!resolved) {
            set_error(out, "ATOMIC_TARGET_RESOLVE_FAILED", strerror(errno));
            return NULL;
        }
        if (stat(resolved, target_st) != 0) {
            int saved = errno; free(resolved); errno = saved;
            set_error(out, "FILE_STAT_FAILED", strerror(errno));
            return NULL;
        }
        if (!S_ISREG(target_st->st_mode)) {
            free(resolved);
            set_error(out, "NOT_REGULAR_FILE", "Atomic replacement requires a regular-file target.");
            return NULL;
        }
        *exists = 1;
        return resolved;
    }
    if (errno != ENOENT) {
        set_error(out, "FILE_STAT_FAILED", strerror(errno));
        return NULL;
    }

    char *copy = strdup(path);
    if (!copy) {
        set_error(out, "OUT_OF_MEMORY", "Allocation failed.");
        return NULL;
    }
    char *slash = strrchr(copy, '/');
    const char *base = copy;
    const char *parent = ".";
    if (slash) {
        *slash = '\0';
        base = slash + 1;
        parent = copy[0] ? copy : "/";
    }
    if (!*base || !strcmp(base, ".") || !strcmp(base, "..")) {
        free(copy);
        set_error(out, "INVALID_ARGUMENT", "Atomic replacement requires a file path, not a directory path.");
        return NULL;
    }
    char *resolved_parent = realpath(parent, NULL);
    if (!resolved_parent) {
        int saved = errno; free(copy); errno = saved;
        set_error(out, "PARENT_RESOLVE_FAILED", strerror(errno));
        return NULL;
    }
    size_t plen = strlen(resolved_parent), blen = strlen(base);
    if (plen > SIZE_MAX - blen - 2) {
        free(resolved_parent); free(copy);
        set_error(out, "OUT_OF_MEMORY", "Path is too long.");
        return NULL;
    }
    char *resolved = malloc(plen + blen + 2);
    if (!resolved) {
        free(resolved_parent); free(copy);
        set_error(out, "OUT_OF_MEMORY", "Allocation failed.");
        return NULL;
    }
    snprintf(resolved, plen + blen + 2, "%s%s%s", resolved_parent,
             plen > 0 && resolved_parent[plen - 1] == '/' ? "" : "/", base);
    free(resolved_parent);
    free(copy);

    /* Recheck the canonical destination in case it appeared during resolution. */
    if (lstat(resolved, &lst) == 0) {
        char *actual = realpath(resolved, NULL);
        if (!actual) {
            int saved = errno; free(resolved); errno = saved;
            set_error(out, "ATOMIC_TARGET_RESOLVE_FAILED", strerror(errno));
            return NULL;
        }
        free(resolved);
        resolved = actual;
        if (stat(resolved, target_st) != 0 || !S_ISREG(target_st->st_mode)) {
            int saved = errno ? errno : EINVAL; free(resolved); errno = saved;
            set_error(out, "NOT_REGULAR_FILE", "Atomic replacement requires a regular-file target.");
            return NULL;
        }
        *exists = 1;
    } else {
        if (errno != ENOENT) {
            int saved = errno; free(resolved); errno = saved;
            set_error(out, "FILE_STAT_FAILED", strerror(errno));
            return NULL;
        }
        memset(target_st, 0, sizeof(*target_st));
        *exists = 0;
    }
    return resolved;
}

static int write_all_fd(int fd, const char *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (n == 0) errno = EIO; return -1; }
        off += (size_t)n;
    }
    return 0;
}



static int flush_output_buffer(int fd, char *buffer, size_t *used) {
    if (*used == 0) return 0;
    if (write_all_fd(fd, buffer, *used) != 0) return -1;
    *used = 0;
    return 0;
}

static int append_output_buffer(int fd, char *buffer, size_t capacity, size_t *used,
                                const char *data, size_t length) {
    while (length > 0) {
        if (*used == capacity && flush_output_buffer(fd, buffer, used) != 0) return -1;
        size_t available = capacity - *used;
        size_t amount = length < available ? length : available;
        memcpy(buffer + *used, data, amount);
        *used += amount;
        data += amount;
        length -= amount;
    }
    return 0;
}

static int same_file_identity(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int same_file_content_version(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
           a->st_gid == b->st_gid && a->st_flags == b->st_flags;
}


static int unsupported_metadata_error(int error_number);

typedef struct {
    acl_t acl;
    acl_type_t acl_type;
    int has_acl;
    unsigned char extattr_sha256[SHA256_DIGEST_LENGTH];
} file_metadata_snapshot;

typedef struct {
    char *name;
    size_t length;
} extattr_name_entry;

static int compare_extattr_names(const void *left, const void *right) {
    const extattr_name_entry *a = left;
    const extattr_name_entry *b = right;
    size_t common = a->length < b->length ? a->length : b->length;
    int compared = memcmp(a->name, b->name, common);
    if (compared != 0) return compared;
    if (a->length < b->length) return -1;
    if (a->length > b->length) return 1;
    return 0;
}

static void sha256_update_u64(SHA256_CTX *context, uint64_t value) {
    unsigned char encoded[8];
    for (size_t i = 0; i < sizeof(encoded); i++)
        encoded[sizeof(encoded) - 1 - i] = (unsigned char)(value >> (i * 8));
    SHA256_Update(context, encoded, sizeof(encoded));
}

static int hash_extattr_namespace(int fd, int attr_namespace, SHA256_CTX *context) {
    unsigned char namespace_tag[4] = {
        (unsigned char)(((uint32_t)attr_namespace >> 24) & 0xff),
        (unsigned char)(((uint32_t)attr_namespace >> 16) & 0xff),
        (unsigned char)(((uint32_t)attr_namespace >> 8) & 0xff),
        (unsigned char)((uint32_t)attr_namespace & 0xff)
    };
    SHA256_Update(context, namespace_tag, sizeof(namespace_tag));

    ssize_t names_size = extattr_list_fd(fd, attr_namespace, NULL, 0);
    if (names_size < 0) {
        if (unsupported_metadata_error(errno)) {
            sha256_update_u64(context, 0);
            return 0;
        }
        return -1;
    }
    if ((uintmax_t)names_size > SIZE_MAX) { errno = EOVERFLOW; return -1; }
    if (names_size == 0) {
        sha256_update_u64(context, 0);
        return 0;
    }

    char *names = malloc((size_t)names_size);
    if (!names) { errno = ENOMEM; return -1; }
    ssize_t names_read = extattr_list_fd(fd, attr_namespace, names, (size_t)names_size);
    if (names_read < 0 || names_read != names_size) {
        int saved = names_read < 0 ? errno : EAGAIN;
        free(names);
        errno = saved;
        return -1;
    }

    size_t capacity = (size_t)names_read / 2 + 1;
    extattr_name_entry *entries = calloc(capacity, sizeof(*entries));
    if (!entries) { free(names); errno = ENOMEM; return -1; }
    size_t count = 0, offset = 0;
    while (offset < (size_t)names_read) {
        size_t name_length = (unsigned char)names[offset++];
        if (name_length == 0 || name_length > EXTATTR_MAXNAMELEN ||
            offset + name_length > (size_t)names_read || count >= capacity) {
            for (size_t i = 0; i < count; i++) free(entries[i].name);
            free(entries); free(names); errno = EIO; return -1;
        }
        entries[count].name = malloc(name_length + 1);
        if (!entries[count].name) {
            for (size_t i = 0; i < count; i++) free(entries[i].name);
            free(entries); free(names); errno = ENOMEM; return -1;
        }
        memcpy(entries[count].name, names + offset, name_length);
        entries[count].name[name_length] = '\0';
        entries[count].length = name_length;
        count++;
        offset += name_length;
    }
    free(names);
    qsort(entries, count, sizeof(*entries), compare_extattr_names);
    sha256_update_u64(context, (uint64_t)count);

    for (size_t i = 0; i < count; i++) {
        extattr_name_entry *entry = &entries[i];
        ssize_t value_size = extattr_get_fd(fd, attr_namespace, entry->name, NULL, 0);
        if (value_size < 0 || (uintmax_t)value_size > SIZE_MAX) {
            int saved = value_size < 0 ? errno : EOVERFLOW;
            for (size_t j = 0; j < count; j++) free(entries[j].name);
            free(entries); errno = saved; return -1;
        }
        size_t allocation = value_size > 0 ? (size_t)value_size : 1;
        unsigned char *value = malloc(allocation);
        if (!value) {
            for (size_t j = 0; j < count; j++) free(entries[j].name);
            free(entries); errno = ENOMEM; return -1;
        }
        ssize_t value_read = extattr_get_fd(fd, attr_namespace, entry->name, value, (size_t)value_size);
        if (value_read < 0 || value_read != value_size) {
            int saved = value_read < 0 ? errno : EAGAIN;
            free(value);
            for (size_t j = 0; j < count; j++) free(entries[j].name);
            free(entries); errno = saved; return -1;
        }
        sha256_update_u64(context, (uint64_t)entry->length);
        SHA256_Update(context, entry->name, entry->length);
        sha256_update_u64(context, (uint64_t)value_read);
        if (value_read > 0) SHA256_Update(context, value, (size_t)value_read);
        free(value);
    }
    for (size_t i = 0; i < count; i++) free(entries[i].name);
    free(entries);
    return 0;
}

static void free_file_metadata_snapshot(file_metadata_snapshot *snapshot) {
    if (!snapshot) return;
    if (snapshot->acl) acl_free(snapshot->acl);
    memset(snapshot, 0, sizeof(*snapshot));
}

static int capture_file_metadata_snapshot(int fd, file_metadata_snapshot *snapshot) {
    memset(snapshot, 0, sizeof(*snapshot));
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_NFS4);
    if (acl) {
        snapshot->acl = acl;
        snapshot->acl_type = ACL_TYPE_NFS4;
        snapshot->has_acl = 1;
    } else {
        if (!unsupported_metadata_error(errno)) return -1;
        acl = acl_get_fd_np(fd, ACL_TYPE_ACCESS);
        if (acl) {
            snapshot->acl = acl;
            snapshot->acl_type = ACL_TYPE_ACCESS;
            snapshot->has_acl = 1;
        } else if (!unsupported_metadata_error(errno)) {
            return -1;
        }
    }

    SHA256_CTX context;
    SHA256_Init(&context);
    if (hash_extattr_namespace(fd, EXTATTR_NAMESPACE_USER, &context) != 0 ||
        hash_extattr_namespace(fd, EXTATTR_NAMESPACE_SYSTEM, &context) != 0) {
        int saved = errno;
        free_file_metadata_snapshot(snapshot);
        errno = saved;
        return -1;
    }
    SHA256_Final(snapshot->extattr_sha256, &context);
    return 0;
}

static int same_file_metadata_snapshot(const file_metadata_snapshot *a,
                                       const file_metadata_snapshot *b) {
    if (a->has_acl != b->has_acl) return 0;
    if (a->has_acl) {
        if (a->acl_type != b->acl_type) return 0;
        int comparison = acl_cmp_np(a->acl, b->acl);
        if (comparison < 0) return -1;
        if (comparison != 0) return 0;
    }
    return memcmp(a->extattr_sha256, b->extattr_sha256, SHA256_DIGEST_LENGTH) == 0;
}

static int verify_file_metadata_snapshot(int fd, const file_metadata_snapshot *baseline,
                                         struct json_object *out, const char *phase) {
    file_metadata_snapshot current;
    if (capture_file_metadata_snapshot(fd, &current) != 0) {
        set_error(out, "ATOMIC_METADATA_SNAPSHOT_FAILED", strerror(errno));
        return -1;
    }
    int comparison = same_file_metadata_snapshot(baseline, &current);
    int saved = errno;
    free_file_metadata_snapshot(&current);
    if (comparison < 0) {
        errno = saved;
        set_error(out, "ATOMIC_METADATA_SNAPSHOT_FAILED", strerror(errno));
        return -1;
    }
    if (comparison == 0) {
        set_error(out, "ATOMIC_TARGET_CHANGED",
                  phase ? phase : "Target ACL or extended attributes changed during atomic staging.");
        errno = EBUSY;
        return -1;
    }
    return 0;
}

#ifdef KERNO_TEST_HOOKS
static void test_pause_at_metadata_checkpoint(const char *phase) {
    const char *selected_phase = getenv("KERNO_TEST_METADATA_BARRIER");
    const char *ready_path = getenv("KERNO_TEST_METADATA_COPY_READY");
    const char *resume_path = getenv("KERNO_TEST_METADATA_COPY_RESUME");
    if (!selected_phase || strcmp(selected_phase, phase) != 0 ||
        !ready_path || !*ready_path || !resume_path || !*resume_path) return;
    int fd = open(ready_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) close(fd);
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    for (int i = 0; i < 30000; i++) {
        if (access(resume_path, F_OK) == 0) return;
        (void)nanosleep(&pause, NULL);
    }
}
#else
static void test_pause_at_metadata_checkpoint(const char *phase) { (void)phase; }
#endif

static int unsupported_metadata_error(int error_number) {
    return error_number == EOPNOTSUPP || error_number == ENOTSUP || error_number == EINVAL;
}

/* Return 1 when an ACL type was copied, 0 when the filesystem does not support it. */
static int copy_acl_type(int source_fd, int destination_fd, acl_type_t type) {
    acl_t acl = acl_get_fd_np(source_fd, type);
    if (!acl) {
        if (unsupported_metadata_error(errno)) return 0;
        return -1;
    }
    if (acl_set_fd_np(destination_fd, acl, type) != 0) {
        int saved = errno;
        acl_free(acl);
        errno = saved;
        return -1;
    }
    acl_free(acl);
    return 1;
}

static int copy_file_acl(int source_fd, int destination_fd) {
    int copied = copy_acl_type(source_fd, destination_fd, ACL_TYPE_NFS4);
    if (copied == 1) return 0;
    if (copied < 0) return -1;
    copied = copy_acl_type(source_fd, destination_fd, ACL_TYPE_ACCESS);
    if (copied < 0) return -1;
    return 0;
}

static int copy_extattr_namespace(int source_fd, int destination_fd, int attr_namespace) {
    ssize_t names_size = extattr_list_fd(source_fd, attr_namespace, NULL, 0);
    if (names_size < 0) {
        if (unsupported_metadata_error(errno)) return 0;
        return -1;
    }
    if (names_size == 0) return 0;
    if ((uintmax_t)names_size > SIZE_MAX) { errno = EOVERFLOW; return -1; }

    char *names = malloc((size_t)names_size);
    if (!names) { errno = ENOMEM; return -1; }
    ssize_t names_read = extattr_list_fd(source_fd, attr_namespace, names, (size_t)names_size);
    if (names_read < 0 || names_read != names_size) {
        int saved = names_read < 0 ? errno : EAGAIN;
        free(names);
        errno = saved;
        return -1;
    }

    size_t offset = 0;
    while (offset < (size_t)names_read) {
        size_t name_length = (unsigned char)names[offset++];
        if (name_length == 0 || name_length > EXTATTR_MAXNAMELEN ||
            offset + name_length > (size_t)names_read) {
            free(names);
            errno = EIO;
            return -1;
        }
        char name[EXTATTR_MAXNAMELEN + 1];
        memcpy(name, names + offset, name_length);
        name[name_length] = '\0';
        offset += name_length;

        ssize_t value_size = extattr_get_fd(source_fd, attr_namespace, name, NULL, 0);
        if (value_size < 0) {
            int saved = errno;
            free(names);
            errno = saved;
            return -1;
        }
        if ((uintmax_t)value_size > SIZE_MAX) {
            free(names);
            errno = EOVERFLOW;
            return -1;
        }
        size_t allocation = value_size > 0 ? (size_t)value_size : 1;
        void *value = malloc(allocation);
        if (!value) {
            free(names);
            errno = ENOMEM;
            return -1;
        }
        ssize_t value_read = extattr_get_fd(source_fd, attr_namespace, name, value, (size_t)value_size);
        if (value_read < 0 || value_read != value_size) {
            int saved = value_read < 0 ? errno : EAGAIN;
            free(value);
            free(names);
            errno = saved;
            return -1;
        }
        ssize_t value_written = extattr_set_fd(destination_fd, attr_namespace, name, value, (size_t)value_read);
        int saved = errno;
        free(value);
        if (value_written < 0 || value_written != value_read) {
            if (value_written >= 0) saved = EIO;
            free(names);
            errno = saved;
            return -1;
        }
    }
    free(names);
    return 0;
}

static int copy_file_metadata(int source_fd, int destination_fd, const struct stat *source_st,
                              struct json_object *out) {
    const fflags_t blocking_flags = UF_IMMUTABLE | UF_APPEND | UF_NOUNLINK |
                                    SF_IMMUTABLE | SF_APPEND | SF_NOUNLINK | SF_SNAPSHOT;
    if ((source_st->st_flags & blocking_flags) != 0) {
        set_error(out, "ATOMIC_FILE_FLAGS_UNSUPPORTED",
                  "Atomic replacement refuses immutable, append-only, no-unlink, or snapshot file flags.");
        return -1;
    }
    if (copy_file_acl(source_fd, destination_fd) != 0) {
        set_error(out, "ATOMIC_ACL_COPY_FAILED", strerror(errno));
        return -1;
    }
    if (copy_extattr_namespace(source_fd, destination_fd, EXTATTR_NAMESPACE_USER) != 0 ||
        copy_extattr_namespace(source_fd, destination_fd, EXTATTR_NAMESPACE_SYSTEM) != 0) {
        set_error(out, "ATOMIC_EXTATTR_COPY_FAILED", strerror(errno));
        return -1;
    }
    if (source_st->st_flags != 0 && fchflags(destination_fd, source_st->st_flags) != 0) {
        set_error(out, "ATOMIC_FILE_FLAGS_COPY_FAILED", strerror(errno));
        return -1;
    }
    return 0;
}

static int sync_committed_file(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int result = fsync(fd);
    int saved = errno;
    if (close(fd) != 0 && result == 0) { result = -1; saved = errno; }
    errno = saved;
    return result;
}

static int sync_parent_directory(const char *path) {
    char *copy = strdup(path);
    if (!copy) { errno = ENOMEM; return -1; }
    char *slash = strrchr(copy, '/');
    const char *parent = ".";
    if (slash) {
        if (slash == copy) {
            slash[1] = '\0';
            parent = copy;
        } else {
            *slash = '\0';
            parent = copy;
        }
    }
    int fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        int saved = errno;
        free(copy);
        errno = saved;
        return -1;
    }
    int result = fsync(fd);
    int saved = errno;
    if (close(fd) != 0 && result == 0) {
        result = -1;
        saved = errno;
    }
    free(copy);
    errno = saved;
    return result;
}

static int refresh_atomic_temp_basic_metadata(int fd, const struct stat *source_st,
                                               struct json_object *out) {
    if ((source_st->st_uid != geteuid() || source_st->st_gid != getegid()) &&
        fchown(fd, source_st->st_uid, source_st->st_gid) != 0) {
        set_error(out, "ATOMIC_METADATA_FAILED", strerror(errno));
        return -1;
    }
    if (fchmod(fd, source_st->st_mode & 07777) != 0) {
        set_error(out, "ATOMIC_METADATA_FAILED", strerror(errno));
        return -1;
    }
    return 0;
}

static int prepare_atomic_temp(const char *target, const struct stat *oldst, int exists,
                               char **tmp_path, struct json_object *out) {
    size_t n = strlen(target);
    if (n > SIZE_MAX - 16) {
        set_error(out, "OUT_OF_MEMORY", "Path is too long.");
        return -1;
    }
    *tmp_path = malloc(n + 16);
    if (!*tmp_path) {
        set_error(out, "OUT_OF_MEMORY", "Allocation failed.");
        return -1;
    }
    snprintf(*tmp_path, n + 16, "%s.tmp.XXXXXX", target);
    int fd = mkstemp(*tmp_path);
    if (fd < 0) {
        int saved = errno; free(*tmp_path); *tmp_path = NULL; errno = saved;
        set_error(out, "TEMP_CREATE_FAILED", strerror(errno));
        return -1;
    }
    if (register_atomic_temp_cleanup(*tmp_path) != 0) {
        int saved = errno; close(fd); unlink(*tmp_path); free(*tmp_path); *tmp_path = NULL; errno = saved;
        set_error(out, "TEMP_PATH_TOO_LONG", strerror(errno));
        return -1;
    }
    mode_t mode;
    if (exists) {
        mode = oldst->st_mode & 07777;
    } else {
        mode_t mask = umask(0);
        (void)umask(mask);
        mode = 0666 & ~mask;
    }
    if (exists && (oldst->st_uid != geteuid() || oldst->st_gid != getegid()) &&
        fchown(fd, oldst->st_uid, oldst->st_gid) != 0) {
        int saved = errno; close(fd); unlink(*tmp_path); clear_atomic_temp_cleanup(); free(*tmp_path); *tmp_path = NULL; errno = saved;
        set_error(out, "ATOMIC_METADATA_FAILED", strerror(errno));
        return -1;
    }
    if (fchmod(fd, mode) != 0) {
        int saved = errno; close(fd); unlink(*tmp_path); clear_atomic_temp_cleanup(); free(*tmp_path); *tmp_path = NULL; errno = saved;
        set_error(out, "ATOMIC_METADATA_FAILED", strerror(errno));
        return -1;
    }
    return fd;
}


static int atomic_write_following(const char *path, const char *data, size_t len,
                                  int create_parents, struct json_object *out) {
    if (create_parents && mkdir_parents(path) != 0) {
        set_error(out, "MKDIR_FAILED", strerror(errno));
        return -1;
    }
    struct stat oldst;
    int exists = 0;
    char *target = resolve_atomic_target(path, &oldst, &exists, out);
    if (!target) return -1;

    int source_fd = -1;
    if (exists) {
        source_fd = open(target, O_RDONLY | O_CLOEXEC);
        if (source_fd < 0) {
            int saved = errno; free(target); errno = saved;
            set_error(out, "FILE_OPEN_FAILED", strerror(errno));
            return -1;
        }
        struct stat opened_st;
        if (fstat(source_fd, &opened_st) != 0 || !same_file_identity(&oldst, &opened_st)) {
            int saved = errno ? errno : EBUSY;
            close(source_fd); free(target); errno = saved;
            set_error(out, "ATOMIC_TARGET_CHANGED", strerror(errno));
            return -1;
        }
    }
    file_metadata_snapshot metadata_baseline;
    memset(&metadata_baseline, 0, sizeof(metadata_baseline));
    if (exists && capture_file_metadata_snapshot(source_fd, &metadata_baseline) != 0) {
        int saved = errno;
        close(source_fd); free(target); errno = saved;
        set_error(out, "ATOMIC_METADATA_SNAPSHOT_FAILED", strerror(errno));
        return -1;
    }

    char *tmp = NULL;
    int fd = prepare_atomic_temp(target, &oldst, exists, &tmp, out);
    if (fd < 0) {
        if (source_fd >= 0) close(source_fd);
        free_file_metadata_snapshot(&metadata_baseline);
        free(target);
        return -1;
    }
    if (exists) {
        struct stat opened_st, path_st;
        if (fsync(source_fd) != 0) {
            int saved = errno;
            close(source_fd); close(fd); unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free_file_metadata_snapshot(&metadata_baseline); free(target); errno = saved;
            set_error(out, "ATOMIC_SOURCE_FSYNC_FAILED", strerror(errno));
            return -1;
        }
        if (fstat(source_fd, &opened_st) != 0 || stat(target, &path_st) != 0 ||
            !same_file_identity(&oldst, &opened_st) || !same_file_content_version(&opened_st, &path_st)) {
            int saved = errno ? errno : EBUSY;
            close(source_fd); close(fd); unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free_file_metadata_snapshot(&metadata_baseline); free(target); errno = saved;
            set_error(out, "ATOMIC_TARGET_CHANGED", strerror(errno));
            return -1;
        }
        oldst = opened_st;
        if (refresh_atomic_temp_basic_metadata(fd, &oldst, out) != 0) {
            int saved = errno;
            close(source_fd); close(fd); unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free_file_metadata_snapshot(&metadata_baseline); free(target); errno = saved;
            return -1;
        }
    }

    int ok = write_all_fd(fd, data, len) == 0;
    int saved = errno;
    if (ok && exists) {
        struct stat descriptor_st, path_st;
        if (fstat(source_fd, &descriptor_st) != 0 || stat(target, &path_st) != 0) {
            ok = 0; saved = errno;
            set_error(out, "ATOMIC_TARGET_STAT_FAILED", strerror(errno));
        } else if (!same_file_content_version(&oldst, &descriptor_st) ||
                   !same_file_content_version(&oldst, &path_st)) {
            ok = 0; saved = EBUSY;
            set_error(out, "ATOMIC_TARGET_CHANGED", "Target content or basic metadata changed while staging atomic write.");
        } else {
            oldst = descriptor_st;
        }
    }
    if (ok && exists && copy_file_metadata(source_fd, fd, &oldst, out) != 0) {
        ok = 0;
        saved = errno;
    }
    if (ok && exists) {
        test_pause_at_metadata_checkpoint("after-copy");
        if (verify_file_metadata_snapshot(source_fd, &metadata_baseline, out,
                "Target ACL or extended attributes changed after metadata copy.") != 0) {
            ok = 0; saved = errno;
        }
    }
    if (ok && exists) {
        struct stat descriptor_st, path_st;
        if (fstat(source_fd, &descriptor_st) != 0 || stat(target, &path_st) != 0) {
            ok = 0; saved = errno;
            set_error(out, "ATOMIC_TARGET_STAT_FAILED", strerror(errno));
        } else if (!same_file_content_version(&oldst, &descriptor_st) ||
                   !same_file_content_version(&oldst, &path_st)) {
            ok = 0; saved = EBUSY;
            set_error(out, "ATOMIC_TARGET_CHANGED", "Target content or basic metadata changed before destination fsync.");
        }
    }
    if (ok && fsync(fd) != 0) { ok = 0; saved = errno; }
    if (ok && exists) test_pause_at_metadata_checkpoint("after-fsync");
    if (ok && exists && verify_file_metadata_snapshot(source_fd, &metadata_baseline, out,
            "Target ACL or extended attributes changed after destination fsync.") != 0) {
        ok = 0; saved = errno;
    }
    if (ok && exists) {
        struct stat descriptor_st, path_st;
        if (fstat(source_fd, &descriptor_st) != 0 || stat(target, &path_st) != 0) {
            ok = 0; saved = errno;
            set_error(out, "ATOMIC_TARGET_STAT_FAILED", strerror(errno));
        } else if (!same_file_content_version(&oldst, &descriptor_st) ||
                   !same_file_content_version(&oldst, &path_st)) {
            ok = 0; saved = EBUSY;
            set_error(out, "ATOMIC_TARGET_CHANGED", "Target content or basic metadata changed during destination fsync.");
        }
    } else if (ok) {
        struct stat current;
        if (lstat(target, &current) == 0) {
            ok = 0; saved = EEXIST;
        } else if (errno != ENOENT) {
            ok = 0; saved = errno;
        }
    }
    if (close(fd) != 0 && ok) { ok = 0; saved = errno; }
    if (ok && exists) test_pause_at_metadata_checkpoint("before-rename");
    if (ok && exists && verify_file_metadata_snapshot(source_fd, &metadata_baseline, out,
            "Target ACL or extended attributes changed immediately before rename.") != 0) {
        ok = 0; saved = errno;
    }
    if (source_fd >= 0 && close(source_fd) != 0 && ok) { ok = 0; saved = errno; }
    free_file_metadata_snapshot(&metadata_baseline);
    if (ok && rename(tmp, target) != 0) {
        ok = 0; saved = errno;
        set_error(out, "ATOMIC_RENAME_FAILED", strerror(errno));
    }
    if (ok) clear_atomic_temp_cleanup();
    if (!ok) {
        unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free(target); errno = saved;
        if (json_object_object_get(out, "error") == NULL)
            set_error(out, "ATOMIC_WRITE_FAILED", strerror(errno));
        return -1;
    }
    free(tmp);
    if (sync_parent_directory(target) != 0 || sync_committed_file(target) != 0) {
        int sync_error = errno;
        free(target);
        errno = sync_error;
        set_error(out, "ATOMIC_WRITE_COMMITTED_DURABILITY_UNCONFIRMED",
                  "The rename committed, but fsync of the committed file or its parent directory failed; durability is unconfirmed.");
        return -1;
    }
    free(target);
    size_t chars = 0;
    for (size_t i = 0; i < len; i++) if (((unsigned char)data[i] & 0xC0) != 0x80) chars++;
    struct json_object *res = result_object();
    json_object_object_add(res, "path", json_object_new_string(path));
    json_object_object_add(res, "bytes_written", json_object_new_int64((int64_t)len));
    json_object_object_add(res, "characters_written", json_object_new_int64((int64_t)chars));
    json_object_object_add(res, "previously_existed", json_object_new_boolean(exists));
    json_object_object_add(res, "atomic", json_object_new_boolean(1));
    set_ok(out, res);
    return 0;
}

static void append_tail(char *buf, size_t *used, size_t cap, const char *data, size_t len) {
    if (!buf || !used || cap < 2 || len == 0) return;
    size_t max = cap - 1;
    if (len >= max) { memcpy(buf, data + len - max, max); *used = max; buf[*used] = '\0'; return; }
    if (*used + len > max) { size_t drop = *used + len - max; memmove(buf, buf + drop, *used - drop); *used -= drop; }
    memcpy(buf + *used, data, len); *used += len; buf[*used] = '\0';
}
static int run_argv(char *const argv[], char *stdout_buf, size_t stdout_cap, char *stderr_buf, size_t stderr_cap, int *exit_code) {
    int outfd[2], errfd[2];
    if (pipe(outfd) != 0) return -1;
    if (pipe(errfd) != 0) { close(outfd[0]); close(outfd[1]); return -1; }
    pid_t pid = fork();
    if (pid < 0) { close(outfd[0]); close(outfd[1]); close(errfd[0]); close(errfd[1]); return -1; }
    if (pid == 0) {
        close(outfd[0]); close(errfd[0]);
        int devnull=open("/dev/null",O_RDONLY);if(devnull>=0){dup2(devnull,STDIN_FILENO);if(devnull>STDERR_FILENO)close(devnull);}
        dup2(outfd[1], STDOUT_FILENO); dup2(errfd[1], STDERR_FILENO);
        close(outfd[1]); close(errfd[1]);
        execv(argv[0], argv); _exit(127);
    }
    close(outfd[1]); close(errfd[1]);
    size_t out_used=0, err_used=0; int out_open=1, err_open=1;
    while (out_open || err_open) {
        fd_set readfds; FD_ZERO(&readfds); int maxfd=-1;
        if (out_open) { FD_SET(outfd[0],&readfds); if(outfd[0]>maxfd)maxfd=outfd[0]; }
        if (err_open) { FD_SET(errfd[0],&readfds); if(errfd[0]>maxfd)maxfd=errfd[0]; }
        int ready=select(maxfd+1,&readfds,NULL,NULL,NULL);
        if(ready<0){if(errno==EINTR)continue;break;}
        if(out_open&&FD_ISSET(outfd[0],&readfds)){
            char temp[4096];ssize_t n=read(outfd[0],temp,sizeof(temp));
            if(n<=0){out_open=0;close(outfd[0]);}else{append_tail(stdout_buf,&out_used,stdout_cap,temp,(size_t)n);}
        }
        if(err_open&&FD_ISSET(errfd[0],&readfds)){
            char temp[4096];ssize_t n=read(errfd[0],temp,sizeof(temp));
            if(n<=0){err_open=0;close(errfd[0]);}else{append_tail(stderr_buf,&err_used,stderr_cap,temp,(size_t)n);}
        }
    }
    if(out_open)close(outfd[0]);if(err_open)close(errfd[0]);
    stdout_buf[out_used]='\0';stderr_buf[err_used]='\0';
    int status=0;while(waitpid(pid,&status,0)<0){if(errno!=EINTR)return -1;}
    *exit_code=WIFEXITED(status)?WEXITSTATUS(status):(128+(WIFSIGNALED(status)?WTERMSIG(status):0));return 0;
}


static int run_argv_timeout(char *const argv[], char *stdout_buf, size_t stdout_cap, char *stderr_buf, size_t stderr_cap, int *exit_code, int timeout_seconds, int *timed_out, const char **termination_signal, int *cleanup_complete) {
    int outfd[2],errfd[2];if(pipe(outfd)!=0)return -1;if(pipe(errfd)!=0){close(outfd[0]);close(outfd[1]);return -1;}
    pid_t pid=fork();if(pid<0){close(outfd[0]);close(outfd[1]);close(errfd[0]);close(errfd[1]);return -1;}
    if(pid==0){(void)setpgid(0,0);close(outfd[0]);close(errfd[0]);int devnull=open("/dev/null",O_RDONLY);if(devnull>=0){dup2(devnull,STDIN_FILENO);if(devnull>STDERR_FILENO)close(devnull);}dup2(outfd[1],STDOUT_FILENO);dup2(errfd[1],STDERR_FILENO);close(outfd[1]);close(errfd[1]);execv(argv[0],argv);_exit(127);}
    (void)setpgid(pid,pid);close(outfd[1]);close(errfd[1]);
    size_t out_used=0,err_used=0;int out_open=1,err_open=1,child_reaped=0,status=0;*timed_out=0;*termination_signal="none";*cleanup_complete=1;
    struct timespec started;clock_gettime(CLOCK_MONOTONIC,&started);double deadline=(double)started.tv_sec+(double)started.tv_nsec/1e9+(double)timeout_seconds;double term_deadline=0;int sent_term=0,sent_kill=0;
    while(out_open||err_open||!child_reaped){
        struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);double current=(double)now.tv_sec+(double)now.tv_nsec/1e9;
        if(!*timed_out&&current>=deadline){*timed_out=1;sent_term=1;term_deadline=current+1.5;*termination_signal="SIGTERM";if(kill(-pid,SIGTERM)!=0&&errno==ESRCH)*termination_signal="already_exited";}
        if(*timed_out&&sent_term&&!sent_kill&&current>=term_deadline){sent_kill=1;*termination_signal="SIGKILL";(void)kill(-pid,SIGKILL);}
        if(!child_reaped){pid_t w=waitpid(pid,&status,WNOHANG);if(w==pid)child_reaped=1;else if(w<0&&errno!=EINTR){child_reaped=1;status=0;}}
        if(!out_open&&!err_open&&child_reaped)break;
        fd_set readfds;FD_ZERO(&readfds);int maxfd=-1;if(out_open){FD_SET(outfd[0],&readfds);if(outfd[0]>maxfd)maxfd=outfd[0];}if(err_open){FD_SET(errfd[0],&readfds);if(errfd[0]>maxfd)maxfd=errfd[0];}
        struct timeval tv={0,1000};int ready=select(maxfd+1,&readfds,NULL,NULL,&tv);if(ready<0&&errno!=EINTR)break;
        if(ready>0&&out_open&&FD_ISSET(outfd[0],&readfds)){char temp[4096];ssize_t n=read(outfd[0],temp,sizeof(temp));if(n<=0){out_open=0;close(outfd[0]);}else append_tail(stdout_buf,&out_used,stdout_cap,temp,(size_t)n);}
        if(ready>0&&err_open&&FD_ISSET(errfd[0],&readfds)){char temp[4096];ssize_t n=read(errfd[0],temp,sizeof(temp));if(n<=0){err_open=0;close(errfd[0]);}else append_tail(stderr_buf,&err_used,stderr_cap,temp,(size_t)n);}
    }
    if(out_open)close(outfd[0]);if(err_open)close(errfd[0]);
    if(!child_reaped){while(waitpid(pid,&status,0)<0){if(errno!=EINTR)return -1;}}
    if(*timed_out){(void)kill(-pid,SIGKILL);struct timespec check_start;clock_gettime(CLOCK_MONOTONIC,&check_start);double end=(double)check_start.tv_sec+(double)check_start.tv_nsec/1e9+1.0;while(kill(-pid,0)==0){struct timespec check;clock_gettime(CLOCK_MONOTONIC,&check);if((double)check.tv_sec+(double)check.tv_nsec/1e9>=end){*cleanup_complete=0;break;}usleep(25000);}if(errno==ESRCH)*cleanup_complete=1;}
    *exit_code=*timed_out?0:(WIFEXITED(status)?WEXITSTATUS(status):(128+(WIFSIGNALED(status)?WTERMSIG(status):0)));return 0;
}

static int remove_path_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)typeflag; (void)ftwbuf;
    return remove(path);
}
static int delete_path(const char *path, int recursive, struct json_object *out) {
    struct stat st;
    if (lstat(path, &st) != 0) { set_error(out, "FILE_STAT_FAILED", strerror(errno)); return -1; }
    int was_directory = S_ISDIR(st.st_mode);
    if (S_ISDIR(st.st_mode)) {
        if (!recursive) { set_error(out, "RECURSION_REQUIRED", "Directory deletion requires recursive=true."); return -1; }
        if (nftw(path, remove_path_cb, 32, FTW_DEPTH | FTW_PHYS) != 0) { set_error(out, "DELETE_FAILED", strerror(errno)); return -1; }
    } else if (unlink(path) != 0) { set_error(out, "DELETE_FAILED", strerror(errno)); return -1; }
    struct json_object *res = result_object();
    json_object_object_add(res, "path", json_object_new_string(path));
    json_object_object_add(res, "deleted", json_object_new_boolean(1));
    json_object_object_add(res, "kind", json_object_new_string(was_directory ? "directory" : "file_or_symlink"));
    set_ok(out, res); return 0;
}


static void __attribute__((unused)) command_text(const char *path, char *buf, size_t cap) {
    if (!buf || cap < 2) return;
    buf[0]='\0';
    char *out=calloc(cap,1), *err=calloc(4096,1);
    if (!out || !err) { free(out); free(err); snprintf(buf,cap,"unavailable: out of memory"); return; }
    char *argv[]={(char *)path,NULL}; int code=0;
    if(run_argv(argv,out,cap,err,4096,&code)==0) {
        if(code==0) snprintf(buf,cap,"%s",out);
        else if(out[0]) snprintf(buf,cap,"%s",out);
        else snprintf(buf,cap,"%s",err[0]?err:"command failed");
    } else snprintf(buf,cap,"unavailable: %s",strerror(errno));
    free(out);free(err);
}
static void system_info(struct json_object *out) {
    char system[128],release[256],version[1024],machine[128],hostname[512];
    char uptime[12001],disk[12001],memory[12001];
    char *uname_s[]={(char *)"/usr/bin/uname",(char *)"-s",NULL};
    char *uname_r[]={(char *)"/usr/bin/uname",(char *)"-r",NULL};
    char *uname_v[]={(char *)"/usr/bin/uname",(char *)"-v",NULL};
    char *uname_m[]={(char *)"/usr/bin/uname",(char *)"-m",NULL};
    char *host[]={(char *)"/bin/hostname",NULL};
    char *up[]={(char *)"/usr/bin/uptime",NULL};
    char *df[]={(char *)"/bin/df",(char *)"-h",NULL};
    char *vm[]={(char *)"/usr/bin/vmstat",(char *)"-s",NULL};
    char *outs[]={system,release,version,machine,hostname,uptime,disk,memory};
    size_t caps[]={sizeof(system),sizeof(release),sizeof(version),sizeof(machine),sizeof(hostname),sizeof(uptime),sizeof(disk),sizeof(memory)};
    char **args[]={uname_s,uname_r,uname_v,uname_m,host,up,df,vm};
    for(int i=0;i<8;i++){
        char *err=calloc(4096,1);int code=0;
        if(!err){snprintf(outs[i],caps[i],"unavailable: out of memory");continue;}
        if(run_argv(args[i],outs[i],caps[i],err,4096,&code)!=0||code!=0){if(!outs[i][0])snprintf(outs[i],caps[i],"%s",err[0]?err:"command failed");}
        free(err);
        size_t n=strlen(outs[i]);while(n>0&&(outs[i][n-1]=='\n'||outs[i][n-1]=='\r'))outs[i][--n]='\0';
    }
    struct json_object *res=result_object();
    json_object_object_add(res,"system",json_object_new_string(system));
    json_object_object_add(res,"release",json_object_new_string(release));
    json_object_object_add(res,"version",json_object_new_string(version));
    json_object_object_add(res,"machine",json_object_new_string(machine));
    json_object_object_add(res,"hostname",json_object_new_string(hostname));
    json_object_object_add(res,"runtime",json_object_new_string("Go SDK + C executor"));
    json_object_object_add(res,"uptime",json_object_new_string(uptime));
    json_object_object_add(res,"disk",json_object_new_string(disk));
    json_object_object_add(res,"memory",json_object_new_string(memory));
    set_ok(out,res);
}
static void tail_logs(struct json_object *input, struct json_object *out) {
    const char *path=jpath(input,"path");int lines=jint(input,"lines",100);
    if(!path||!*path||lines<1||lines>2000){set_error(out,"INVALID_ARGUMENT","path is required and lines must be 1..2000.");return;}
    char number[16];snprintf(number,sizeof(number),"%d",lines);
    char *stdout_buf=calloc(120001,1),*stderr_buf=calloc(12001,1);
    if(!stdout_buf||!stderr_buf){free(stdout_buf);free(stderr_buf);set_error(out,"OUT_OF_MEMORY","Allocation failed.");return;}
    char *argv[]={(char *)"/usr/bin/tail",(char *)"-n",number,(char *)"--",(char *)path,NULL};int code=0;
    if(run_argv(argv,stdout_buf,120001,stderr_buf,12001,&code)!=0){free(stdout_buf);free(stderr_buf);set_error(out,"LOG_READ_FAILED",strerror(errno));return;}
    struct json_object *res=result_object();json_object_object_add(res,"returncode",json_object_new_int(code));json_object_object_add(res,"stdout",json_object_new_string(stdout_buf));json_object_object_add(res,"stderr",json_object_new_string(stderr_buf));set_ok(out,res);free(stdout_buf);free(stderr_buf);
}
static const char *find_bytes(const char *haystack, size_t hay_len, const char *needle, size_t needle_len) {
    if (!needle_len || needle_len > hay_len) return NULL;
    size_t last = hay_len - needle_len;
    for (size_t i = 0; i <= last; i++) if (haystack[i] == needle[0] && memcmp(haystack + i, needle, needle_len) == 0) return haystack + i;
    return NULL;
}


static void replace_file_python(struct json_object *input, struct json_object *out) {
    const char *path = jpath(input, "path");
    struct json_object *old_obj = NULL, *new_obj = NULL;
    if (!path || !*path ||
        !json_object_object_get_ex(input, "old_text", &old_obj) || !old_obj ||
        json_object_get_type(old_obj) != json_type_string ||
        !json_object_object_get_ex(input, "new_text", &new_obj) || !new_obj ||
        json_object_get_type(new_obj) != json_type_string) {
        set_error(out, "INVALID_ARGUMENT", "path, non-empty old_text and new_text are required.");
        return;
    }
    const char *old = json_object_get_string(old_obj);
    const char *replacement = json_object_get_string(new_obj);
    size_t olen = (size_t)json_object_get_string_len(old_obj);
    size_t rlen = (size_t)json_object_get_string_len(new_obj);
    if (olen == 0) {
        set_error(out, "INVALID_ARGUMENT", "old_text 不能为空");
        return;
    }
    int replace_all = jbool(input, "replace_all", 0);

    struct stat oldst;
    int exists = 0;
    char *target = resolve_atomic_target(path, &oldst, &exists, out);
    if (!target) return;
    if (!exists) {
        free(target);
        set_error(out, "FILE_OPEN_FAILED", "Target file does not exist.");
        return;
    }

    int source_fd = open(target, O_RDONLY | O_CLOEXEC);
    if (source_fd < 0) {
        int saved = errno; free(target); errno = saved;
        set_error(out, "FILE_OPEN_FAILED", strerror(errno));
        return;
    }
    struct stat source_st;
    if (fstat(source_fd, &source_st) != 0 || !S_ISREG(source_st.st_mode) ||
        !same_file_identity(&oldst, &source_st)) {
        int saved = errno ? errno : EINVAL;
        close(source_fd); free(target); errno = saved;
        set_error(out, "NOT_REGULAR_FILE", "Only regular files can be replaced.");
        return;
    }
    file_metadata_snapshot metadata_baseline;
    if (capture_file_metadata_snapshot(source_fd, &metadata_baseline) != 0) {
        int saved = errno;
        close(source_fd); free(target); errno = saved;
        set_error(out, "ATOMIC_METADATA_SNAPSHOT_FAILED", strerror(errno));
        return;
    }

    char *tmp = NULL;
    int dest_fd = prepare_atomic_temp(target, &source_st, 1, &tmp, out);
    if (dest_fd < 0) {
        close(source_fd); free_file_metadata_snapshot(&metadata_baseline); free(target);
        return;
    }
    struct stat path_st;
    if (fsync(source_fd) != 0) {
        int saved = errno;
        close(source_fd); close(dest_fd); unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free_file_metadata_snapshot(&metadata_baseline); free(target); errno = saved;
        set_error(out, "ATOMIC_SOURCE_FSYNC_FAILED", strerror(errno));
        return;
    }
    if (fstat(source_fd, &source_st) != 0 || stat(target, &path_st) != 0 ||
        !same_file_identity(&oldst, &source_st) || !same_file_content_version(&source_st, &path_st)) {
        int saved = errno ? errno : EBUSY;
        close(source_fd); close(dest_fd); unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free_file_metadata_snapshot(&metadata_baseline); free(target); errno = saved;
        set_error(out, "ATOMIC_TARGET_CHANGED", strerror(errno));
        return;
    }
    oldst = source_st;
    if (refresh_atomic_temp_basic_metadata(dest_fd, &source_st, out) != 0) {
        int saved = errno;
        close(source_fd); close(dest_fd); unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free_file_metadata_snapshot(&metadata_baseline); free(target); errno = saved;
        return;
    }

    const size_t chunk_size = 64 * 1024;
    if (olen > SIZE_MAX - chunk_size) {
        close(source_fd); close(dest_fd); unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free_file_metadata_snapshot(&metadata_baseline); free(target);
        set_error(out, "OUT_OF_MEMORY", "Search pattern is too large.");
        return;
    }
    size_t pending_cap = olen + chunk_size;
    char *pending = malloc(pending_cap);
    if (!pending) {
        close(source_fd); close(dest_fd); unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free_file_metadata_snapshot(&metadata_baseline); free(target);
        set_error(out, "OUT_OF_MEMORY", "Allocation failed.");
        return;
    }

    size_t pending_len = 0;
    int64_t matches = 0, replacements = 0;
    char chunk[64 * 1024];
    char output_buffer[64 * 1024];
    size_t output_used = 0;
    int failed = 0, saved_error = 0;
    for (;;) {
        ssize_t n = read(source_fd, chunk, sizeof(chunk));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { failed = 1; saved_error = errno; break; }
        if (n == 0) break;
        memcpy(pending + pending_len, chunk, (size_t)n);
        pending_len += (size_t)n;

        size_t consumed = 0;
        while (pending_len - consumed >= olen) {
            const char *search = pending + consumed;
            size_t remaining = pending_len - consumed;
            const char *found = find_bytes(search, remaining, old, olen);
            if (found) {
                size_t prefix = (size_t)(found - search);
                if (prefix && append_output_buffer(dest_fd, output_buffer, sizeof(output_buffer), &output_used, search, prefix) != 0) {
                    failed = 1; saved_error = errno; break;
                }
                if (matches == INT64_MAX) {
                    failed = 1; saved_error = EOVERFLOW; break;
                }
                matches++;
                if (replace_all || replacements == 0) {
                    if (rlen && append_output_buffer(dest_fd, output_buffer, sizeof(output_buffer), &output_used, replacement, rlen) != 0) {
                        failed = 1; saved_error = errno; break;
                    }
                    replacements++;
                } else if (append_output_buffer(dest_fd, output_buffer, sizeof(output_buffer), &output_used, old, olen) != 0) {
                    failed = 1; saved_error = errno; break;
                }
                consumed += prefix + olen;
            } else {
                size_t safe = remaining - olen + 1;
                if (append_output_buffer(dest_fd, output_buffer, sizeof(output_buffer), &output_used, search, safe) != 0) {
                    failed = 1; saved_error = errno; break;
                }
                consumed += safe;
            }
        }
        if (failed) break;
        if (consumed > 0) {
            pending_len -= consumed;
            if (pending_len) memmove(pending, pending + consumed, pending_len);
        }
        if (failed) break;
    }
    if (!failed && pending_len &&
        append_output_buffer(dest_fd, output_buffer, sizeof(output_buffer), &output_used, pending, pending_len) != 0) {
        failed = 1; saved_error = errno;
    }
    if (!failed && flush_output_buffer(dest_fd, output_buffer, &output_used) != 0) {
        failed = 1; saved_error = errno;
    }
    free(pending);
    if (!failed && copy_file_metadata(source_fd, dest_fd, &source_st, out) != 0) {
        failed = 1;
        saved_error = errno;
    }
    if (!failed) {
        test_pause_at_metadata_checkpoint("after-copy");
        if (verify_file_metadata_snapshot(source_fd, &metadata_baseline, out,
                "Target ACL or extended attributes changed after metadata copy.") != 0) {
            failed = 1; saved_error = errno;
        }
    }
    if (!failed) {
        struct stat latest_source, current_target;
        if (fstat(source_fd, &latest_source) != 0) {
            failed = 1; saved_error = errno;
        } else if (stat(target, &current_target) != 0) {
            failed = 1; saved_error = errno;
        } else if (!same_file_content_version(&source_st, &latest_source) ||
                   !same_file_content_version(&source_st, &current_target)) {
            failed = 1; saved_error = EBUSY;
            set_error(out, "ATOMIC_TARGET_CHANGED", "Target content or basic metadata changed before destination fsync.");
        }
    }
    if (!failed && fsync(dest_fd) != 0) { failed = 1; saved_error = errno; }
    if (!failed) test_pause_at_metadata_checkpoint("after-fsync");
    if (!failed && verify_file_metadata_snapshot(source_fd, &metadata_baseline, out,
            "Target ACL or extended attributes changed after destination fsync.") != 0) {
        failed = 1; saved_error = errno;
    }
    if (!failed) {
        struct stat latest_source, current_target;
        if (fstat(source_fd, &latest_source) != 0 || stat(target, &current_target) != 0) {
            failed = 1; saved_error = errno;
            set_error(out, "ATOMIC_TARGET_STAT_FAILED", strerror(errno));
        } else if (!same_file_content_version(&source_st, &latest_source) ||
                   !same_file_content_version(&source_st, &current_target)) {
            failed = 1; saved_error = EBUSY;
            set_error(out, "ATOMIC_TARGET_CHANGED", "Target content or basic metadata changed during destination fsync.");
        }
    }
    if (close(dest_fd) != 0 && !failed) { failed = 1; saved_error = errno; }
    if (!failed) test_pause_at_metadata_checkpoint("before-rename");
    if (!failed && verify_file_metadata_snapshot(source_fd, &metadata_baseline, out,
            "Target ACL or extended attributes changed immediately before rename.") != 0) {
        failed = 1; saved_error = errno;
    }
    if (close(source_fd) != 0 && !failed) { failed = 1; saved_error = errno; }
    free_file_metadata_snapshot(&metadata_baseline);
    if (failed) {
        unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free(target); errno = saved_error;
        if (json_object_object_get(out, "error") == NULL)
            set_error(out, "ATOMIC_REPLACE_FAILED", strerror(errno));
        return;
    }

    if (matches == 0) {
        unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free(target);
        struct json_object *res = result_object();
        json_object_object_add(res, "success", json_object_new_boolean(0));
        json_object_object_add(res, "path", json_object_new_string(path));
        json_object_object_add(res, "matches", json_object_new_int64(0));
        json_object_object_add(res, "replacements", json_object_new_int64(0));
        json_object_object_add(res, "reason", json_object_new_string("未找到匹配文本"));
        set_ok(out, res);
        return;
    }

    if (rename(tmp, target) != 0) {
        int saved = errno; unlink(tmp); clear_atomic_temp_cleanup(); free(tmp); free(target); errno = saved;
        set_error(out, "ATOMIC_REPLACE_FAILED", strerror(errno));
        return;
    }
    clear_atomic_temp_cleanup();
    free(tmp);
    if (sync_parent_directory(target) != 0 || sync_committed_file(target) != 0) {
        int sync_error = errno;
        free(target);
        errno = sync_error;
        set_error(out, "ATOMIC_REPLACE_COMMITTED_DURABILITY_UNCONFIRMED",
                  "The rename committed, but fsync of the committed file or its parent directory failed; durability is unconfirmed.");
        return;
    }
    free(target);
    struct json_object *res = result_object();
    json_object_object_add(res, "success", json_object_new_boolean(1));
    json_object_object_add(res, "path", json_object_new_string(path));
    json_object_object_add(res, "matches", json_object_new_int64(matches));
    json_object_object_add(res, "replacements", json_object_new_int64(replacements));
    json_object_object_add(res, "atomic", json_object_new_boolean(1));
    set_ok(out, res);
}

static void handle(struct json_object *in, struct json_object *out) {
    const char *version = jstr(in, "protocol_version");
    const char *task_id = jstr(in, "task_id");
    const char *op = jstr(in, "operation");
    struct json_object *input = NULL;
    if (!version || strcmp(version, "1") != 0 || !task_id || !*task_id || strlen(task_id) > 128) {
        set_error(out, "INVALID_REQUEST", "protocol_version=1 and a valid task_id are required."); return;
    }
    if (!op || !json_object_object_get_ex(in, "input", &input) || !input || json_object_get_type(input) != json_type_object) {
        set_error(out, "INVALID_REQUEST", "operation and object input are required."); return;
    }
    if (!strcmp(op, "system.info")) { system_info(out); return; }
    if (!strcmp(op, "logs.tail")) { tail_logs(input, out); return; }
    if (!strcmp(op, "file.replace")) { replace_file_python(input, out); return; }
    if (!strcmp(op, "shell.exec")) {
        const char *cmd = jstr(input, "command");
        if (!cmd || !*cmd || strlen(cmd) > 131072) { set_error(out, "INVALID_ARGUMENT", "command must be 1..131072 bytes."); return; }
        char *stdout_buf = calloc(SHELL_STDOUT_LIMIT + 1, 1), *stderr_buf = calloc(SHELL_STDERR_LIMIT + 1, 1);
        if (!stdout_buf || !stderr_buf) { free(stdout_buf); free(stderr_buf); set_error(out, "OUT_OF_MEMORY", "Allocation failed."); return; }
        int timeout_seconds=jint(input,"timeout_seconds",30);if(timeout_seconds<1||timeout_seconds>300){free(stdout_buf);free(stderr_buf);set_error(out,"INVALID_ARGUMENT","timeout_seconds must be 1..300.");return;}
        char *argv[] = {"/bin/sh", "-c", (char *)cmd, NULL};
        int code = 0,timed_out=0,cleanup_complete=1;const char *termination_signal="none";
        if (run_argv_timeout(argv, stdout_buf, SHELL_STDOUT_LIMIT + 1, stderr_buf, SHELL_STDERR_LIMIT + 1, &code, timeout_seconds, &timed_out, &termination_signal, &cleanup_complete) != 0) { free(stdout_buf); free(stderr_buf); set_error(out, "COMMAND_FAILED", strerror(errno)); return; }
        struct json_object *res = result_object();
        json_object_object_add(res, "stdout", json_object_new_string(stdout_buf));
        json_object_object_add(res, "stderr", json_object_new_string(stderr_buf));
        if(timed_out)json_object_object_add(res,"returncode",json_object_new_null());else json_object_object_add(res,"returncode",json_object_new_int(code));
        json_object_object_add(res, "timed_out", json_object_new_boolean(timed_out));
        if(timed_out){json_object_object_add(res,"termination_signal",json_object_new_string(termination_signal));json_object_object_add(res,"cleanup_complete",json_object_new_boolean(cleanup_complete));}
        set_ok(out, res);
        free(stdout_buf); free(stderr_buf);
        return;
    }
    if (!strcmp(op, "directory.list")) {
        const char *path = jpath(input, "path");
        if (!path || !*path) { set_error(out, "INVALID_ARGUMENT", "path is required."); return; }
        list_directory(path, out); return;
    }
    if (!strcmp(op, "file.read")) {
        const char *path = jpath(input, "path");
        if (!path || !*path) { set_error(out, "INVALID_ARGUMENT", "path is required."); return; }
        int max = jint(input, "max_bytes", 200000);
        if (max < 1 || max > FILE_LIMIT) { set_error(out, "INVALID_ARGUMENT", "max_bytes is outside policy limits."); return; }
        read_file_limited(path, (size_t)max, out); return;
    }
    if (!strcmp(op, "file.write")) {
        const char *path = jpath(input, "path");
        struct json_object *content_obj = NULL;
        if (!path || !*path || !json_object_object_get_ex(input, "content", &content_obj) || !content_obj || json_object_get_type(content_obj) != json_type_string) {
            set_error(out, "INVALID_ARGUMENT", "path and string content are required."); return;
        }
        const char *content = json_object_get_string(content_obj);
        size_t content_len = (size_t)json_object_get_string_len(content_obj);
        int create_parents = jbool(input, "create_parents", 0);
        if (jbool(input, "atomic", 0)) {
            atomic_write_following(path, content, content_len, create_parents, out);
        } else {
            write_text_file(path, content, content_len, create_parents, out);
        }
        return;
    }
    if (!strcmp(op, "file.edit")) {
        const char *path = jpath(input, "path"), *old = jstr(input, "old_text"), *replacement = jstr(input, "new_text");
        if (!path || !old || !*old || !replacement) { set_error(out, "INVALID_ARGUMENT", "path, non-empty old_text and new_text are required."); return; }
        struct json_object *tmp = result_object();
        if (read_file(path, FILE_LIMIT, tmp) != 0) { json_object_put(tmp); set_error(out, "FILE_READ_FAILED", "Could not read target file."); return; }
        struct json_object *r = NULL; json_object_object_get_ex(tmp, "result", &r);
        struct json_object *cv = NULL; json_object_object_get_ex(r, "content", &cv);
        const char *source = cv ? json_object_get_string(cv) : "";
        size_t slen = strlen(source), olen = strlen(old), rlen = strlen(replacement);
        int expected = jint(input, "expected_matches", 1), matches = 0;
        const char *scan = source;
        while ((scan = strstr(scan, old)) != NULL) { matches++; scan += olen; }
        if (matches != expected) { json_object_put(tmp); set_error(out, "MATCH_COUNT_MISMATCH", "old_text match count does not equal expected_matches."); return; }
        long long newlen_signed = (long long)slen + (long long)matches * ((long long)rlen - (long long)olen);
        if (newlen_signed < 0 || newlen_signed > FILE_LIMIT) { json_object_put(tmp); set_error(out, "FILE_TOO_LARGE", "Edited content exceeds 2 MiB."); return; }
        size_t newlen = (size_t)newlen_signed;
        if (newlen > FILE_LIMIT) { json_object_put(tmp); set_error(out, "FILE_TOO_LARGE", "Edited content exceeds 2 MiB."); return; }
        char *dest = malloc(newlen + 1);
        if (!dest) { json_object_put(tmp); set_error(out, "OUT_OF_MEMORY", "Allocation failed."); return; }
        const char *p = source; char *d = dest;
        while ((scan = strstr(p, old)) != NULL) {
            size_t n = (size_t)(scan - p); memcpy(d, p, n); d += n;
            memcpy(d, replacement, rlen); d += rlen; p = scan + olen;
        }
        strcpy(d, p);
        json_object_put(tmp);
        atomic_write(path, dest, strlen(dest), 0, out);
        free(dest); return;
    }
    if (!strcmp(op, "file.delete")) {
        const char *path = jpath(input, "path");
        if (!path || !*path) { set_error(out, "INVALID_ARGUMENT", "A non-empty path is required."); return; }
        delete_path(path, jbool(input, "recursive", 0), out); return;
    }
    if (!strcmp(op, "file.move")) {
        const char *src = jpath(input, "source"), *dst = jpath(input, "destination");
        if (!src || !*src || !dst || !*dst) { set_error(out, "INVALID_ARGUMENT", "source and destination are required."); return; }
        struct stat st; char final_path[PATH_MAX];
        if (lstat(dst, &st) == 0 && !jbool(input, "overwrite", 0)) { set_error(out, "DESTINATION_EXISTS", "Destination exists and overwrite=false."); return; }
        if (stat(dst, &st) == 0 && S_ISDIR(st.st_mode)) { const char *base=strrchr(src,'/'); base=base?base+1:src; snprintf(final_path,sizeof(final_path),"%s/%s",dst,base); }
        else snprintf(final_path,sizeof(final_path),"%s",dst);
        char *argv[]={(char *)"/bin/mv",(char *)src,(char *)dst,NULL}; char *o=calloc(4096,1),*e=calloc(4096,1);int code=0;
        if(!o||!e){free(o);free(e);set_error(out,"OUT_OF_MEMORY","Allocation failed.");return;}
        if(run_argv(argv,o,4096,e,4096,&code)!=0||code!=0){set_error(out,"MOVE_FAILED",e[0]?e:"mv failed");free(o);free(e);return;}
        struct json_object *res = result_object(); json_object_object_add(res,"result",json_object_new_string(final_path)); set_ok(out,res); free(o);free(e); return;
    }
    if (!strcmp(op, "service.status") || !strcmp(op, "service.control")) {
        const char *service = jstr(input, "service");
        const char *action = !strcmp(op, "service.status") ? "status" : jstr(input, "action");
        if (!service || !*service || !action) { set_error(out, "INVALID_ARGUMENT", "service and action are required."); return; }
        if (strspn(service, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-") != strlen(service)) { set_error(out, "INVALID_ARGUMENT", "Invalid service name."); return; }
        if (strcmp(action,"status") && strcmp(action,"start") && strcmp(action,"reload") && strcmp(action,"stop") && strcmp(action,"restart")) { set_error(out, "INVALID_ARGUMENT", "Unsupported service action."); return; }
        char *stdout_buf = calloc(OUTPUT_LIMIT + 1, 1), *stderr_buf = calloc(OUTPUT_LIMIT + 1, 1);
        if (!stdout_buf || !stderr_buf) { free(stdout_buf); free(stderr_buf); set_error(out, "OUT_OF_MEMORY", "Allocation failed."); return; }
        char *argv[] = {"/usr/sbin/service", (char *)service, (char *)action, NULL};
        int code = 0;
        if (run_argv(argv, stdout_buf, OUTPUT_LIMIT + 1, stderr_buf, OUTPUT_LIMIT + 1, &code) != 0) { free(stdout_buf); free(stderr_buf); set_error(out, "SERVICE_COMMAND_FAILED", strerror(errno)); return; }
        struct json_object *res = result_object();
        json_object_object_add(res, "service", json_object_new_string(service));
        json_object_object_add(res, "action", json_object_new_string(action));
        json_object_object_add(res, "exit_code", json_object_new_int(code));
        json_object_object_add(res, "stdout", json_object_new_string(stdout_buf));
        json_object_object_add(res, "stderr", json_object_new_string(stderr_buf));
        set_ok(out, res); free(stdout_buf); free(stderr_buf); return;
    }
    set_error(out, "UNKNOWN_OPERATION", "Operation is not supported by this executor version.");
}
int main(int argc, char **argv) {
    if (install_atomic_temp_signal_handlers() != 0) return 3;
    if (argc == 2 && strcmp(argv[1], "--list-operations") == 0) {
        puts("[\"system.info\",\"shell.exec\",\"directory.list\",\"file.read\",\"file.write\",\"file.replace\",\"file.edit\",\"file.move\",\"file.delete\",\"service.status\",\"service.control\",\"logs.tail\"]");
        return 0;
    }
    size_t cap = 4096, n = 0;
    char *line = malloc(cap);
    if (!line) return 3;
    int ch = 0, oversized = 0;
    while ((ch = fgetc(stdin)) != EOF && ch != '\n') {
        if (n == INPUT_LIMIT) { oversized = 1; break; }
        if (n + 1 >= cap) {
            size_t next_cap = cap * 2;
            if (next_cap > INPUT_LIMIT + 1) next_cap = INPUT_LIMIT + 1;
            char *grown = realloc(line, next_cap);
            if (!grown) { free(line); return 3; }
            line = grown;
            cap = next_cap;
        }
        line[n++] = (char)ch;
    }
    if (!oversized && ch == '\n' && fgetc(stdin) != EOF) oversized = 1;
    if (oversized || (n == 0 && ch == EOF)) {
        struct json_object *out = result_object();
        set_error(out, "INVALID_REQUEST", "Expected exactly one JSON request <= 32 MiB on stdin.");
        puts(json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN));
        json_object_put(out); free(line); return 2;
    }
    line[n] = '\0';
    struct json_object *in = json_tokener_parse(line);
    struct json_object *out = result_object();
    if (!in) set_error(out, "INVALID_JSON", "Input is not valid JSON.");
    else {
        handle(in, out);
        const char *task_id = jstr(in, "task_id");
        if (task_id) json_object_object_add(out, "task_id", json_object_new_string(task_id));
    }
    puts(json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN));
    json_object_put(out);
    if (in) json_object_put(in);
    free(line);
    return 0;
}
