#include <fuse.h>
#include <unistd.h>
#include "def.h"

static int dedupfs_utime(const char *path, struct utimbuf *ubuf) {
    DEBUG_MESSAGE("[utime]" << path);
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    return utime(full_path, ubuf);
}

static int dedupfs_unlink(const char *path) {
    DEBUG_MESSAGE("unlink: " << path);
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    return unlink(full_path);
}

static int dedupfs_readlink(const char *path, char *buf, size_t size) {
    DEBUG_MESSAGE("[readlink]" << full_path);
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    return readlink(full_path, buf, size - 1);
}

static int dedupfs_link(const char *oldpath, const char *newpath) {
    DEBUG_MESSAGE("[link]" << "dest: " << full_new << " src: " << full_old);
    char full_old[1024];
    char full_new[1024];
    snprintf(full_old, sizeof(full_old), "%s%s", BACKEND, oldpath);
    snprintf(full_new, sizeof(full_new), "%s%s", BACKEND, newpath);
    return link(full_old, full_new);
}

static int dedupfs_symlink(const char *oldpath, const char *newpath) {
    DEBUG_MESSAGE("[symlink]" << "dest" << full_new << " src: " << full_old);
    char full_old[1024];
    char full_new[1024];
    snprintf(full_old, sizeof(full_old), "%s%s", BACKEND, oldpath);
    snprintf(full_new, sizeof(full_new), "%s%s", BACKEND, newpath);
    return symlink(full_old, full_new);
}

/*static int cdcfs_truncate(const char *path, off_t size) {
    int res;
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    DEBUG_MESSAGE("[truncate]" << path << " size: " << size);

    res = truncate(full_path, size);
    if (res == -1) {
        return -errno;
    }
    return 0;
}

static int cdcfs_ftruncate(const char *path, off_t size, fuse_file_info *fi) {
    int res;
    return 0;
    DEBUG_MESSAGE("[ftruncate]" << path << ", size: " << size);

    if  (fi == NULL) {
        return -errno;
    }

    res = ftruncate(file_handler[fi->fh].fh, size);
    if (res == -1) {
        return -errno;
    }
    return 0;
}*/