#define FUSE_USE_VERSION 30

#include <filesystem>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include "file.h"
#include "utils.h"
#include "dir.h"

static void dedupfs_leave(void *param){
    uint64_t chunk_count = 0;
    off_t virtual_write_size = 0;
    for (const auto& file_pair: path_to_iNum){
        INUM_TYPE iNum = file_pair.second;
        uint64_t file_group_count = mapping_table[iNum].group_pos.size()-1;
        chunk_count += file_group_count;
        virtual_write_size += mapping_table[iNum].virtual_size;
    }
    PRINT_MESSAGE("\n----------------------------------------leaving CDCFS !!!----------------------------------------");
    PRINT_MESSAGE("total write size: " << (float)total_write_size / 1073741824 << "GB");
    PRINT_MESSAGE("real write size: " << (float)real_write_size / 1073741824 << "GB");
    PRINT_MESSAGE("total pending size: " << (float)total_pending_size / 1073741824 << "GB");
    PRINT_MESSAGE("virtual write size: " << (float)virtual_write_size / 1073741824 << "GB");
    PRINT_MESSAGE("total dedup rate: " << 100 - (float)(real_write_size + total_pending_size) / total_write_size * 100 << "%");
    PRINT_MESSAGE("host read size: " << host_read_size);
    PRINT_MESSAGE("host read size(GB): " << (float)host_read_size / 1073741824 << "GB");
    PRINT_MESSAGE("FUSE read size: " << fuse_read_size);
    PRINT_MESSAGE("FUSE read size(GB): " << (float)fuse_read_size / 1073741824 << "GB");
    PRINT_MESSAGE("read amplication: " << (float)fuse_read_size / host_read_size * 100 << "%");
    PRINT_MESSAGE("average chunking size: " << (float)total_write_size / chunk_count);
    #ifdef RECORD_LATENCY
    // output bandwidth of each page to file
    std::ofstream lat_output(RECORD_LATENCY_PATH);
    for (const auto& file_pair: path_to_iNum){
        lat_output << "file_name: " << file_pair.first << std::endl;
        lat_output << "page_count: " << each_file_read_bandwidth[file_pair.second].lat.size() << std::endl;
        // output latency and count
        for (uint32_t i = 0; i < each_file_read_bandwidth[file_pair.second].lat.size(); i++){
            lat_output << each_file_read_bandwidth[file_pair.second].lat[i] << " " << each_file_read_bandwidth[file_pair.second].count[i] << std::endl;
        }
    }
    #endif
}

static struct fuse_operations dedupfs_oper = {
    .getattr        = dedupfs_getattr,
    .readlink       = dedupfs_readlink,
    .mkdir          = dedupfs_mkdir,
    // .unlink         = dedupfs_unlink,
    .rmdir          = dedupfs_rmdir,
    .symlink        = dedupfs_symlink,
    .link           = dedupfs_link,
    //.truncate       = dedupfs_truncate,
    .utime          = dedupfs_utime,
    .open           = dedupfs_open,
    .read           = dedupfs_read,
    .write          = dedupfs_write,
    .release        = dedupfs_release,
    .opendir        = dedupfs_opendir,
    .readdir        = dedupfs_readdir,
    .releasedir     = dedupfs_releasedir,
    .destroy        = dedupfs_leave,
    .create         = dedupfs_create,
    //.ftruncate      = dedupfs_ftruncate,
};

int main(int argc, char *argv[]) {
    // remove old chunk store
    struct stat info;
    if (stat(BACKEND CHUNK_STORE, &info) != 0)
        PRINT_MESSAGE("old chunk store not found");
    else if (info.st_mode & S_IFDIR) {
        PRINT_MESSAGE("found old chunk store, removing");
        std::filesystem::remove_all(BACKEND CHUNK_STORE);
    }
    // remove every file in backend directory.
    bool has_confirm = false;
    char reply;
    for (const auto& entry : std::filesystem::directory_iterator(BACKEND)){
        if (!has_confirm){
            std::cout << "WARNING: backend directory is not empty, all files in it will be removed!![y|n]";
            std::cin >> reply;
            has_confirm = true;
            if (reply == 'y' || reply == 'Y'){
                PRINT_MESSAGE("removing please wait!!");
                has_confirm = true;
            }
            else{
                PRINT_MESSAGE("Can not start DedupFS due to not empty backend directory");
                return 0;
            }
        }
        std::filesystem::remove_all(entry.path());
    }
    // init CDCFS data structure
    PRINT_MESSAGE("----------------------------------------entering CDCFS !!----------------------------------------");
    for (INUM_TYPE iNum = 0; iNum < MAX_INODE_NUM - 1; ++iNum)
        free_iNum.insert(iNum);
    for(FILE_HANDLER_INDEX_TYPE file_handler = 0; file_handler < MAX_FILE_HANDLER - 1; ++file_handler)
        free_file_handler.insert(file_handler);
    // build chunk store
    mode_t old_mask = umask(0);  // Temporarily set umask to 0
    mkdir(BACKEND CHUNK_STORE, 0766);
    umask(old_mask); // Restore the original umask after operation
    // init fastcdc engine
    cdc = fastcdc_init(0, CHUNK_SIZE, MAX_GROUP_SIZE);
    ctx = &cdc;
    // start FUSE daemon
    return fuse_main(argc, argv, &dedupfs_oper, NULL);
}