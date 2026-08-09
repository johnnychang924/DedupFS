#include <iostream>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <unistd.h>  // for pread
#include <map>
#include <set>
#include <openssl/sha.h>
#include <linux/fs.h>        /* Definition of FICLONE* constants */
#include <sys/ioctl.h>
#include <unordered_set>

#include "def.h"

struct rewrite_req_struct{
    INUM_TYPE iNum;
    off_t logical_offset;
    char buffer[SECTOR_SIZE];
};

struct RewriteChunkCmp {
    bool operator()(const std::pair<off_t, off_t>& a, const std::pair<off_t, off_t>& b) const {
        return a.first < b.first;
    }
};

off_t rewrite_file_size = 0;
uint64_t total_rewrite_size = 0;    // Total rewrite size(include duplicate page)
uint64_t real_rewrite_size = 0;     // real rewrite size to the disk(exclude deuplicate page)
uint64_t max_inline_rewrite_chunks = 0; // max chunks processed in a single inline_rewrite_handler call

int virtual_file_read_fh[MAX_INODE_NUM] = { 0 };

extern mapping_table_entry mapping_table[MAX_INODE_NUM];
extern std::shared_mutex mapping_table_remap_mutex[MAX_INODE_NUM];

bool running = true;
int rewrite_write_fh;
int rewrite_read_fh;

std::condition_variable_any inline_rewrite_cv;
std::shared_mutex rewrite_queue_mutex;
std::deque<rewrite_req_struct> rewrite_queue;

alignas(4096) char rewrite_buffer[ONESHOT_REWRITE_SIZE];        // align with 4096 for direct I/O

/*
**  inline rewrite worker
*/
void remap_rewrite_worker(){
    rewrite_write_fh = open(BACKEND CHUNK_STORE REWRITE_FILE_PATH, O_RDWR | O_CREAT | O_DIRECT, 0666);
    rewrite_read_fh = open(BACKEND CHUNK_STORE REWRITE_FILE_PATH, O_RDONLY | O_DIRECT, 0666);
    if (rewrite_write_fh == -1){
        PRINT_WARNING("Critical Error: Can not open rewrite write file handler in inline rewrite worker");
        return;
    }
    if (rewrite_read_fh == -1){
        PRINT_WARNING("Critical Error: Can not open rewrite read file handler in inline rewrite worker");
        return;
    }
    int result = posix_fadvise(rewrite_read_fh, 0, 0, POSIX_FADV_RANDOM);
    if (result != 0) PRINT_WARNING("Can not set POSIX_FADV_RANDOM");
    while (running){
        std::deque<rewrite_req_struct> local_batch;
        {
            std::unique_lock<std::shared_mutex> lock(rewrite_queue_mutex);
            inline_rewrite_cv.wait(lock, []{ return rewrite_queue.size() > 1024 || !running; });
            if (!running) break;
            std::swap(local_batch, rewrite_queue);
        }
        std::map<INUM_TYPE, std::set<std::pair<off_t, off_t>, RewriteChunkCmp>> rewrite_map;
        int rewrite_buffer_size = 0;
        off_t rewrite_file_cursor = rewrite_file_size;
        // concat small write request into a big single write systemcall to improve write speed
        for (auto& req : local_batch){
            if (!running) [[unlikely]] break;
            // flush buffer
            if (rewrite_buffer_size == ONESHOT_REWRITE_SIZE) {
                int ret = pwrite(rewrite_write_fh, rewrite_buffer, ONESHOT_REWRITE_SIZE, rewrite_file_size);
                if (ret != ONESHOT_REWRITE_SIZE) PRINT_WARNING("Can not flush rewrite buffer!!!");
                rewrite_buffer_size = 0;
                real_rewrite_size += ONESHOT_REWRITE_SIZE;
                rewrite_file_size += ONESHOT_REWRITE_SIZE;
            }
            // fill in buffer
            memcpy(rewrite_buffer + rewrite_buffer_size, req.buffer, SECTOR_SIZE);
            rewrite_buffer_size += SECTOR_SIZE;
            if (rewrite_buffer_size > ONESHOT_REWRITE_SIZE) PRINT_WARNING("ERROR: rewrite buffer overflow");
            // store each page's position in rewrite file
            rewrite_map[req.iNum].insert({req.logical_offset, rewrite_file_cursor});
            rewrite_file_cursor += SECTOR_SIZE;
        }
        // flush buffer although it's not full
        if (rewrite_buffer_size != 0){
            int ret = pwrite(rewrite_write_fh, rewrite_buffer, rewrite_buffer_size, rewrite_file_size);
            if (ret != rewrite_buffer_size) PRINT_WARNING("Can not flush rewrite buffer!!!");
            real_rewrite_size += rewrite_buffer_size;
            rewrite_file_size += rewrite_buffer_size;
        }
        int result = posix_fadvise(rewrite_read_fh, 0, 0, POSIX_FADV_RANDOM);        // remind kernel that this file is random I/O(just in case)
        if (result != 0) PRINT_WARNING("Can not set POSIX_FADV_RANDOM");
        // update remap table in mapping table
        for (auto& [iNum, chunks] : rewrite_map){
            if (!running) [[unlikely]] break;
            max_inline_rewrite_chunks = std::max(max_inline_rewrite_chunks, (uint64_t)chunks.size());
            total_rewrite_size += chunks.size() * SECTOR_SIZE;
            {
                std::unique_lock<std::shared_mutex> write_lock(mapping_table_remap_mutex[iNum]);
                for (auto &[logical_offset, src_off]: chunks){
                    mapping_table[iNum].remap[logical_offset] = src_off;
                }
            }
        }
    }
}