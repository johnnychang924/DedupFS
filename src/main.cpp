#define FUSE_USE_VERSION 30

#include <filesystem>
#include <fstream>
#include "file.h"
#include "utils.h"
#include "dir.h"

static void cdcfs_leave(void *param){
    PRINT_MESSAGE("\n----------------------------------------leaving CDCFS !!!----------------------------------------");
    //PRINT_MESSAGE("total write size: " << (float)total_write_size / 1000000000 << "GB");
    //PRINT_MESSAGE("total dedup rate: " << (float)total_dedup_size / total_write_size * 100 << "%");
    //PRINT_MESSAGE("host read size: " << host_read_size);
    //PRINT_MESSAGE("FUSE read size: " << fuse_read_size);
    //PRINT_MESSAGE("SSD read size(possibly): " << ssd_read_size);
}

static struct fuse_operations dedupfs_oper = {
    .getattr        = dedupfs_getattr,
    .readlink       = dedupfs_readlink,
    .mkdir          = dedupfs_mkdir,
    .unlink         = dedupfs_unlink,
    .rmdir          = dedupfs_rmdir,
    .symlink        = dedupfs_symlink,
    .link           = dedupfs_link,
    //.truncate       = dedupfs_truncate,
    .utime          = dedupfs_utime,
    .open           = dedupfs_open,
    .read           = cdcfs_read,
    .write          = cdcfs_write,
    .release        = cdcfs_release,
    .opendir        = dedupfs_opendir,
    .readdir        = dedupfs_readdir,
    .releasedir     = dedupfs_releasedir,
    .destroy        = cdcfs_leave,
    .create         = dedupfs_create,
    //.ftruncate      = dedupfs_ftruncate,
};

int main(int argc, char *argv[]) {
    // remove every file in backend directory.
    bool has_confirm = false;
    char reply;
    for (const auto& entry : std::filesystem::directory_iterator(BACKEND)){
        if (!has_confirm){
            std::cout << "WARNING: BACKEND directory is not empty, all files in it will be removed!![y|n]";
            std::cin >> reply;
            has_confirm = true;
            if (reply == 'y' || reply == 'Y')
                has_confirm = true;
            else
                return 0;
        }
        std::filesystem::remove_all(entry.path());
    }
    // init CDCFS data structure
    PRINT_MESSAGE("----------------------------------------entering CDCFS !!----------------------------------------");
    for (INUM_TYPE iNum = 0; iNum < MAX_INODE_NUM - 1; ++iNum)
        free_iNum.insert(iNum);
    for(FILE_HANDLER_INDEX_TYPE file_handler = 0; file_handler < MAX_FILE_HANDLER - 1; ++file_handler)
        free_file_handler.insert(file_handler);
    // init fastcdc engine
    cdc = fastcdc_init(0, BLOCK_SIZE, MAX_GROUP_SIZE);
    ctx = &cdc;
    // start FUSE daemon
    return fuse_main(argc, argv, &dedupfs_oper, NULL);
}