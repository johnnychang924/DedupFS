#include <fuse.h>
#include <dirent.h>
#include "def.h"

static int dedupfs_opendir(const char *path, struct fuse_file_info *fi) {
    DEBUG_MESSAGE("[open dir]" << path);
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    DIR *dp = opendir(full_path);
    if (dp == NULL)
        return -1;
    fi->fh = (uint64_t)dp;
    return 0;
}

static int dedupfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
        off_t offset, struct fuse_file_info *fi) {
    DEBUG_MESSAGE("[read dir]" << path);
    DIR *dp = (DIR *)fi->fh;;
    struct dirent *de;
    if (dp == NULL)
        return -1;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, CHUNK_STORE + 1) == 0) continue;
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }
    return 0;
}

static int dedupfs_releasedir(const char *path, struct fuse_file_info *fi) {
    DEBUG_MESSAGE("[release dir]" << path);
    return closedir((DIR *) fi->fh);
}

static int dedupfs_mkdir(const char *path, mode_t mode) {
    DEBUG_MESSAGE("[create dir]" << path);
    char full_path[1024];
    bool error = false;
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    int res = mkdir(full_path, mode);
    if (res == -1){
        perror("can not make directory: ");
        error = true;
    }
    snprintf(full_path, sizeof(full_path), "%s%s%s", BACKEND, CHUNK_STORE, path);
    res = mkdir(full_path, mode);
    if (res == -1){
        perror("can not make directory in chunk store: ");
        error = true;
    }
    return error ? -errno : 0;
}

static int dedupfs_rmdir(const char *path) {
    DEBUG_MESSAGE("[remove dir]" << path);
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    return rmdir(full_path);
}