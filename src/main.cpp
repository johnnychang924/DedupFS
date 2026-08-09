#define FUSE_USE_VERSION 30

#include <filesystem>
#include <fstream>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#include "file.h"
#include "utils.h"
#include "dir.h"

std::thread rewrite_thread;

/*
**  Called on filesystem exit. 
*/
static void dedupfs_leave(void *param){
    uint64_t chunk_count = 0;
    off_t virtual_write_size = 0;
    uint64_t total_read_req = read_req_align + read_req_misalign + read_req_frag;
    int gigabyte = pow(2, 30);
    for (const auto& file_pair: path_to_iNum){
        INUM_TYPE iNum = file_pair.second;
        uint64_t file_group_count = mapping_table[iNum].group_pos.size()-1;
        chunk_count += file_group_count;
        virtual_write_size += mapping_table[iNum].virtual_size;
    }
    PRINT_MESSAGE("\n----------------------------------------leaving CDCFS !!!----------------------------------------");
    PRINT_MESSAGE("total write size: " << (float)total_write_size / gigabyte << "GB");
    PRINT_MESSAGE("real write size: " << (float)real_write_size / gigabyte << "GB");
    PRINT_MESSAGE("total padding size: " << (float)total_padding_size / gigabyte << "GB");
    PRINT_MESSAGE("virtual write size: " << (float)virtual_write_size / gigabyte << "GB");
    PRINT_MESSAGE("total dedup rate: " << 100 - (float)(real_write_size + total_padding_size) / total_write_size * 100 << "%");
    PRINT_MESSAGE("host read size: " << host_read_size);
    PRINT_MESSAGE("host read size(GB): " << (float)host_read_size / gigabyte << "GB");
    PRINT_MESSAGE("FUSE read size: " << fuse_read_size);
    PRINT_MESSAGE("FUSE read size(GB): " << (float)fuse_read_size / gigabyte << "GB");
    PRINT_MESSAGE("read amplication: " << (float)fuse_read_size / host_read_size * 100 << "%");
    PRINT_MESSAGE("average chunking size: " << (float)total_write_size / chunk_count);
    PRINT_MESSAGE("Total rewrite size(GB): " << (float)total_rewrite_size / gigabyte << "GB");
    PRINT_MESSAGE("Total rewrite size: " << total_rewrite_size);
    PRINT_MESSAGE("Real rewrite size(GB): " << (float)real_rewrite_size / gigabyte << "GB");
    PRINT_MESSAGE("Real rewrite size: " << real_rewrite_size);
    PRINT_MESSAGE("Max inline rewrite chunks (single handler call): " << max_inline_rewrite_chunks);
    PRINT_MESSAGE("remap fragmentation: " << (float)remap_pread_count / remap_req_count);
    PRINT_MESSAGE("Total read req#: " << total_read_req);
    PRINT_MESSAGE("Aligned read req#: " << read_req_align);
    PRINT_MESSAGE("Misaligned read req#: " << read_req_misalign);
    PRINT_MESSAGE("Fragmented read req#: " << read_req_frag);

    // stop rewrite thread
    #ifdef INLINE_REWRITE
    running = false;
    inline_rewrite_cv.notify_one();
    rewrite_thread.join();
    #endif
}

/*
**  FUSE opration struct
*/
static struct fuse_operations dedupfs_oper = {
    .getattr        = dedupfs_getattr,
    .readlink       = dedupfs_readlink,
    .mkdir          = dedupfs_mkdir,
    // .unlink         = dedupfs_unlink,
    .rmdir          = dedupfs_rmdir,
    .symlink        = dedupfs_symlink,
    .link           = dedupfs_link,
    // .truncate       = dedupfs_truncate,
    .utime          = dedupfs_utime,
    .open           = dedupfs_open,
    .read           = dedupfs_read,
    .write          = dedupfs_write,
    .flush          = dedupfs_flush,
    .release        = dedupfs_release,
    .opendir        = dedupfs_opendir,
    .readdir        = dedupfs_readdir,
    .releasedir     = dedupfs_releasedir,
    .destroy        = dedupfs_leave,
    .create         = dedupfs_create,
    //.ftruncate      = dedupfs_ftruncate,
};

/*
**  print out current system setting
*/
void print_system_config(){
    #ifdef PENDING
        PRINT_MESSAGE("enable pending!!");
    #endif
    #ifdef INLINE_REWRITE
        PRINT_MESSAGE("enable inline rewrite!!");
    #endif
    #ifdef CHUNK_CACHE_SIZE
        PRINT_MESSAGE("enable chunk cache, size: " << CHUNK_CACHE_SIZE);
    #endif
    #if defined(CHUNK_CACHE_SIZE) && !defined(PENDING)
        PRINT_WARNING("You have enable chunk cache, but not enable pending. This might be wrong");
        exit(EXIT_FAILURE);
    #endif
}

/*
**  remove old metadata or data in BACKEND folder
*/
void remove_old_metadata(){
    // remove old chunk store
    struct stat info;
    if (stat(BACKEND, &info) != 0 || !(info.st_mode & S_IFDIR)){
        PRINT_WARNING("BACKEND folder not exist or is a file, consider mkdir or point BACKEND to correct folder in config.h");
        exit(EXIT_FAILURE);
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
                exit(EXIT_FAILURE);
            }
        }
        std::filesystem::remove_all(entry.path());
    }
}

/*
**  FUSE daemon's entry point
*/
int main(int argc, char *argv[]) {
    remove_old_metadata();
    print_system_config();
    PRINT_MESSAGE("----------------------------------------entering CDCFS !!----------------------------------------");

    // init CDCFS data structure
    for (INUM_TYPE iNum = 0; iNum < MAX_INODE_NUM - 1; ++iNum)
        free_iNum.push(iNum);
    for(FILE_HANDLER_INDEX_TYPE file_handler = 0; file_handler < MAX_FILE_HANDLER - 1; ++file_handler)
        free_file_handler.push(file_handler);

    mode_t old_mask = umask(0);  // Temporarily set umask to 0
    // build chunk store
    mkdir(BACKEND CHUNK_STORE, 0766);
    umask(old_mask); // Restore the original umask after operation

    // init chunker setting
    cdc_setting = fastcdc_init(512, CHUNK_SIZE, MAX_GROUP_SIZE);

    // start rewrite worker thread if enable rewrite
    #ifdef INLINE_REWRITE
    rewrite_thread = std::thread(remap_rewrite_worker);
    #endif

    // start FUSE service(lazy way)
    return fuse_main(argc, argv, &dedupfs_oper, NULL);
}
