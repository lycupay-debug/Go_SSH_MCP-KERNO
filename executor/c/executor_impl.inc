#include <json-c/json.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
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

#define INPUT_LIMIT (4 * 1024 * 1024)
#define OUTPUT_LIMIT (1024 * 1024)
#define SHELL_STDOUT_LIMIT 120000
#define SHELL_STDERR_LIMIT 40000
#define FILE_LIMIT (4 * 1024 * 1024)

static const char *jstr(struct json_object *o, const char *key) {
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v) || !v ||
        json_object_get_type(v) != json_type_string) return NULL;
    return json_object_get_string(v);
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
    if (!ok) {
        unlink(tmp); free(tmp); errno = saved;
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
    const char *path=jstr(input,"path");int lines=jint(input,"lines",100);
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
    const char *path=jstr(input,"path");
    struct json_object *old_obj=NULL,*new_obj=NULL;
    if(!path||!*path||!json_object_object_get_ex(input,"old_text",&old_obj)||!old_obj||json_object_get_type(old_obj)!=json_type_string||!json_object_object_get_ex(input,"new_text",&new_obj)||!new_obj||json_object_get_type(new_obj)!=json_type_string){set_error(out,"INVALID_ARGUMENT","path, non-empty old_text and new_text are required.");return;}
    const char *old=json_object_get_string(old_obj),*replacement=json_object_get_string(new_obj);
    size_t olen=(size_t)json_object_get_string_len(old_obj),rlen=(size_t)json_object_get_string_len(new_obj);
    if(olen==0){set_error(out,"INVALID_ARGUMENT","old_text 不能为空");return;}
    struct json_object *tmp=result_object();if(read_file(path,(size_t)INT_MAX,tmp)!=0){json_object_put(tmp);set_error(out,"FILE_READ_FAILED","Could not read target file.");return;}
    struct json_object *r=NULL,*cv=NULL;json_object_object_get_ex(tmp,"result",&r);if(r)json_object_object_get_ex(r,"content",&cv);
    const char *source=cv?json_object_get_string(cv):"";size_t slen=cv?(size_t)json_object_get_string_len(cv):0;
    int matches=0;size_t scan_off=0;
    while(scan_off<slen){const char *found=find_bytes(source+scan_off,slen-scan_off,old,olen);if(!found)break;matches++;scan_off=(size_t)(found-source)+olen;}
    if(matches==0){json_object_put(tmp);struct json_object *res=result_object();json_object_object_add(res,"success",json_object_new_boolean(0));json_object_object_add(res,"path",json_object_new_string(path));json_object_object_add(res,"matches",json_object_new_int(0));json_object_object_add(res,"replacements",json_object_new_int(0));json_object_object_add(res,"reason",json_object_new_string("未找到匹配文本"));set_ok(out,res);return;}
    int replace_all=jbool(input,"replace_all",0);int replacements=replace_all?matches:1;
    long long nlen_signed=(long long)slen+(long long)replacements*((long long)rlen-(long long)olen);
    if(nlen_signed<0||nlen_signed>INT_MAX){json_object_put(tmp);set_error(out,"FILE_TOO_LARGE","Edited content exceeds the supported text size.");return;}
    size_t nlen=(size_t)nlen_signed;char *dest=malloc(nlen+1);if(!dest){json_object_put(tmp);set_error(out,"OUT_OF_MEMORY","Allocation failed.");return;}
    size_t source_off=0,dest_off=0,done=0;
    while(source_off<slen&&done<(size_t)replacements){const char *found=find_bytes(source+source_off,slen-source_off,old,olen);if(!found)break;size_t match_off=(size_t)(found-source);size_t prefix=match_off-source_off;if(prefix){memcpy(dest+dest_off,source+source_off,prefix);dest_off+=prefix;}if(rlen){memcpy(dest+dest_off,replacement,rlen);dest_off+=rlen;}source_off=match_off+olen;done++;if(!replace_all)break;}
    if(source_off<slen){memcpy(dest+dest_off,source+source_off,slen-source_off);dest_off+=slen-source_off;}dest[dest_off]='\0';json_object_put(tmp);
    struct json_object *write_result=result_object();if(write_text_file(path,dest,dest_off,0,write_result)!=0){json_object_put(write_result);free(dest);set_error(out,"FILE_WRITE_FAILED","Could not write edited file.");return;}
    json_object_put(write_result);free(dest);struct json_object *res=result_object();json_object_object_add(res,"success",json_object_new_boolean(1));json_object_object_add(res,"path",json_object_new_string(path));json_object_object_add(res,"matches",json_object_new_int(matches));json_object_object_add(res,"replacements",json_object_new_int(replacements));set_ok(out,res);
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
        const char *path = jstr(input, "path");
        if (!path || !*path) { set_error(out, "INVALID_ARGUMENT", "path is required."); return; }
        list_directory(path, out); return;
    }
    if (!strcmp(op, "file.read")) {
        const char *path = jstr(input, "path");
        if (!path || !*path) { set_error(out, "INVALID_ARGUMENT", "path is required."); return; }
        int max = jint(input, "max_bytes", 200000);
        if (max < 1 || max > FILE_LIMIT) { set_error(out, "INVALID_ARGUMENT", "max_bytes is outside policy limits."); return; }
        read_file_limited(path, (size_t)max, out); return;
    }
    if (!strcmp(op, "file.write")) {
        const char *path = jstr(input, "path"), *content = jstr(input, "content");
        if (!path || !*path || !content || strlen(content) > FILE_LIMIT) { set_error(out, "INVALID_ARGUMENT", "path and content are required; content must be <= 2 MiB."); return; }
        write_text_file(path, content, strlen(content), jbool(input, "create_parents", 0), out); return;
    }
    if (!strcmp(op, "file.edit")) {
        const char *path = jstr(input, "path"), *old = jstr(input, "old_text"), *replacement = jstr(input, "new_text");
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
        const char *path = jstr(input, "path");
        if (!path || !*path) { set_error(out, "INVALID_ARGUMENT", "A non-empty path is required."); return; }
        char resolved[PATH_MAX];const char *check_path=realpath(path,resolved)?resolved:path;
        if (!strcmp(check_path, "/") || !strcmp(check_path, "/etc") || !strcmp(check_path, "/usr") || !strcmp(check_path, "/var") || !strcmp(check_path, "/opt")) { set_error(out, "INVALID_ARGUMENT", "Refusing to delete a protected system path."); return; }
        delete_path(path, jbool(input, "recursive", 0), out); return;
    }
    if (!strcmp(op, "file.move")) {
        const char *src = jstr(input, "source"), *dst = jstr(input, "destination");
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
static char *executor_error_copy(const char *value) { return strdup(value ? value : "operation failed"); }

int executor_read_file_raw(const char *path, size_t max_bytes, char **data, size_t *data_len, int *truncated, char **error_code, char **error_message) {
    if (data) *data = NULL; if (data_len) *data_len = 0; if (truncated) *truncated = 0;
    if (error_code) *error_code = NULL; if (error_message) *error_message = NULL;
    if (!path || !*path || !data || !data_len || !truncated || max_bytes < 1 || max_bytes > 2000000) {
        if (error_code) *error_code = executor_error_copy("INVALID_ARGUMENT");
        if (error_message) *error_message = executor_error_copy("path is required and max_bytes must be 1..2000000.");
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { if(error_code)*error_code=executor_error_copy("FILE_OPEN_FAILED");if(error_message)*error_message=executor_error_copy(strerror(errno));return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { int saved=errno;close(fd);if(error_code)*error_code=executor_error_copy("NOT_REGULAR_FILE");if(error_message)*error_message=executor_error_copy("Only regular files are readable.");errno=saved;return -1; }
    char *buf = malloc(max_bytes + 1);
    if (!buf) { close(fd);if(error_code)*error_code=executor_error_copy("OUT_OF_MEMORY");if(error_message)*error_message=executor_error_copy("Allocation failed.");return -1; }
    size_t n=0;
    while(n<max_bytes+1){ssize_t r=read(fd,buf+n,max_bytes+1-n);if(r<0&&errno==EINTR)continue;if(r<0){int saved=errno;free(buf);close(fd);if(error_code)*error_code=executor_error_copy("FILE_READ_FAILED");if(error_message)*error_message=executor_error_copy(strerror(saved));return -1;}if(r==0)break;n+=(size_t)r;}
    close(fd);*truncated=n>max_bytes;if(*truncated)n=max_bytes;*data=buf;*data_len=n;return 0;
}

char *executor_write_text_json(const char *path, const char *data, size_t len, int create_parents) {
    struct json_object *out=result_object();
    if (!out) return NULL;
    if (!path || !*path || (!data && len>0)) set_error(out,"INVALID_ARGUMENT","path and content are required.");
    else write_text_file(path,data ? data : "",len,create_parents,out);
    const char *encoded=json_object_to_json_string_ext(out,JSON_C_TO_STRING_PLAIN);char *copy=encoded?strdup(encoded):NULL;json_object_put(out);return copy;
}

char *executor_process_json(const char *line) {
    struct json_object *out = result_object();
    if (!out) return NULL;
    struct json_object *in = line ? json_tokener_parse(line) : NULL;
    if (!in) set_error(out, "INVALID_REQUEST", "Input must be valid JSON.");
    else handle(in, out);
    const char *encoded = json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN);
    char *copy = encoded ? strdup(encoded) : NULL;
    if (in) json_object_put(in);
    json_object_put(out);
    return copy;
}
void executor_free(void *p) { free(p); }

#ifndef EXECUTOR_LIBRARY
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--list-operations") == 0) {
        puts("[\"system.info\",\"shell.exec\",\"directory.list\",\"file.read\",\"file.write\",\"file.replace\",\"file.edit\",\"file.move\",\"file.delete\",\"service.status\",\"service.control\",\"logs.tail\"]");
        return 0;
    }
    char *line = NULL; size_t cap = 0;
    ssize_t n = getline(&line, &cap, stdin);
    if (n < 0 || n > INPUT_LIMIT) {
        struct json_object *out = result_object();
        set_error(out, "INVALID_REQUEST", "Expected one JSON request <= 4 MiB on stdin.");
        puts(json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN));
        json_object_put(out); free(line); return 2;
    }
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
#endif /* EXECUTOR_LIBRARY */
