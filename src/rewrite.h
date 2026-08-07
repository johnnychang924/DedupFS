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
#include <thread>

#include "lfu_list.h"
#include "def.h"

struct rewrite_req_struct{
    INUM_TYPE iNum;
    off_t logical_offset;
    char buffer[SECTOR_SIZE];
};

// Compare only by logical_offset, ignoring buffer pointer,
// so duplicate offsets are deduplicated in a set.
struct RewriteChunkCmp {
    bool operator()(const std::pair<off_t, off_t>& a, const std::pair<off_t, off_t>& b) const {
        return a.first < b.first;
    }
};

std::unordered_map<FP_TYPE, off_t> rewrite_fp_store;
off_t rewrite_file_size = 0;
LFUList lfu;

uint64_t total_rewrite_size = 0;    // Total rewrite size(include duplicate page)
uint64_t real_rewrite_size = 0;     // real rewrite size to the disk(exclude deuplicate page)
uint64_t max_inline_rewrite_chunks = 0; // max chunks processed in a single inline_rewrite_handler call

int virtual_file_read_fh[MAX_INODE_NUM] = { 0 };

extern mapping_table_entry mapping_table[MAX_INODE_NUM];
extern std::shared_mutex mapping_table_mutex[MAX_INODE_NUM];
extern std::shared_mutex mapping_table_remap_mutex[MAX_INODE_NUM];
extern inline PATH_TYPE get_path(INUM_TYPE iNum);
extern inline int build_virtual_file(mapping_table_entry& entry, int fh);
extern inline INUM_TYPE get_inum(PATH_TYPE path_str);

bool running = true;
int rewrite_write_fh;
int rewrite_read_fh;

/*
* rewrite the offset in a single file(thread safe)
* @iNum: the file iNum of target file
* @rewrite_chunk: the offset and content of the chunk to be rewrited
*/
void rewrite_handler(INUM_TYPE iNum, std::set<std::pair<off_t, off_t>, RewriteChunkCmp> rewrite_chunk, INUM_TYPE rewrite_file_iNum){
    std::string file_name = get_path(iNum);
    if (file_name == "") [[unlikely]] {
        PRINT_WARNING("can not find file path, iNum: " << iNum);
        return;
    }
    // create a shadow file to rebuild in the background
    std::string shadow_file_name = file_name + ".temp";
    std::string full_shadow_file_path = BACKEND + shadow_file_name;
    std::string full_file_path = BACKEND + file_name;
    struct stat file_st;
    if (stat(full_file_path.c_str(), &file_st) != 0) [[unlikely]] {
        PRINT_WARNING("REWRITE failed: can not find file stat, path: " << full_file_path << " ,iNum: " << iNum);
        return;
    }
    int shadow_file_fh = creat(full_shadow_file_path.c_str(), file_st.st_mode & 07777);
    mapping_table_entry new_mapping_table_entry;
    GROUP_IDX_TYPE cur_group_idx;
    auto rewrite_chunk_it = rewrite_chunk.begin();
    off_t prev_cur_process_offset = -1;  // for debug use
    off_t cur_process_offset = 0;
    {
    std::shared_lock<std::shared_mutex> read_lock(mapping_table_mutex[iNum]);
    new_mapping_table_entry.logical_size = mapping_table[iNum].logical_size;
    new_mapping_table_entry.real_size = mapping_table[iNum].real_size;
    // loop file's each group
    for (cur_group_idx = 0; cur_group_idx < mapping_table[iNum].group_pos.size(); cur_group_idx++){
        if (!running) return;
        // check if this group needs to be rewritten
        off_t start_group_offset = mapping_table[iNum].group_logical_offset[cur_group_idx];
        off_t end_group_offset = start_group_offset + mapping_table[iNum].group_pos[cur_group_idx]->length;
        INUM_TYPE group_ori_iNum = mapping_table[iNum].group_pos[cur_group_idx]->iNum;
        while (cur_process_offset < end_group_offset){
            bool need_rewrite = rewrite_chunk_it != rewrite_chunk.end() && rewrite_chunk_it->first < end_group_offset;
            need_rewrite = need_rewrite && rewrite_chunk_it->first + SECTOR_SIZE <= (off_t)mapping_table[iNum].logical_size;
            bool at_first = cur_process_offset == start_group_offset;
            if (cur_process_offset <= prev_cur_process_offset) [[unlikely]] {
                PRINT_WARNING("rewrite error: cur_process_offset not moving forward");
                PRINT_WARNING("group_idx: " << cur_group_idx);
                PRINT_WARNING("start_group_offset: " << start_group_offset);
                PRINT_WARNING("prev_cur_process_offset: " << prev_cur_process_offset);
                PRINT_WARNING("cur_process_offset: " << cur_process_offset);
                PRINT_WARNING("end_group_offset: " << end_group_offset);
                PRINT_WARNING("next offset to rewrite: " << (rewrite_chunk_it != rewrite_chunk.end() ? rewrite_chunk_it->first : -1));
                PRINT_WARNING("logical_size: " << mapping_table[iNum].logical_size);
                PRINT_WARNING("need_rewrite: " << need_rewrite);
                PRINT_WARNING("at_first: " << at_first);
                return;
            }
            prev_cur_process_offset = cur_process_offset;
            if (at_first && !need_rewrite) [[likely]] {     // fast forward
                new_mapping_table_entry.group_logical_offset.push_back(start_group_offset);
                new_mapping_table_entry.group_pos.push_back(mapping_table[iNum].group_pos[cur_group_idx]);
                cur_process_offset = end_group_offset;
            }
            else if(need_rewrite && cur_process_offset == rewrite_chunk_it->first){     // rewrite page
                chunk_addr *new_chunk_addr = new chunk_addr{ rewrite_file_iNum, rewrite_chunk_it->second, SECTOR_SIZE };
                new_mapping_table_entry.group_logical_offset.push_back(cur_process_offset);
                new_mapping_table_entry.group_pos.push_back(new_chunk_addr);
                cur_process_offset += SECTOR_SIZE;
                rewrite_chunk_it++;
            }
            else{       // create partial group
                uint16_t front_gap = cur_process_offset - start_group_offset;
                off_t new_group_pos_off = mapping_table[iNum].group_pos[cur_group_idx]->offset + front_gap;
                size_t new_group_len;
                if (need_rewrite)
                    new_group_len = rewrite_chunk_it->first - cur_process_offset;
                else
                    new_group_len = end_group_offset - cur_process_offset;
                if (new_group_len <= 0) [[unlikely]] {
                    PRINT_WARNING("Invalid new_group_len: " << new_group_len);
                }
                chunk_addr *new_chunk_addr = new chunk_addr{ group_ori_iNum, new_group_pos_off, new_group_len };
                new_mapping_table_entry.group_logical_offset.push_back(cur_process_offset);
                new_mapping_table_entry.group_pos.push_back(new_chunk_addr);
                cur_process_offset += new_group_len;
            }
            uint64_t end_logical_page = cur_process_offset / CHUNK_SIZE;
            for(GROUP_IDX_TYPE i = new_mapping_table_entry.group_idx.size(); i <= end_logical_page; i++){
                new_mapping_table_entry.group_idx.push_back(new_mapping_table_entry.group_pos.size() - 1);
            }
        }
    }
    } // release shared read_lock before build_virtual_file
    // build shadow virtual file from new_mapping_table_entry outside the lock
    // (ioctl FICLONERANGE is slow; reads to iNum are unblocked during this phase)
    build_virtual_file(new_mapping_table_entry, shadow_file_fh);
    close(shadow_file_fh);
    int new_read_fh = open(full_shadow_file_path.c_str(), O_RDONLY);
    if (new_read_fh == -1) [[unlikely]] {
        PRINT_WARNING("REWRITE failed: cannot open shadow file for reading");
        return;
    }
    // rename outside the lock — only changes dir entry, old fds still point to old inode
    if (rename(full_shadow_file_path.c_str(), full_file_path.c_str()) != 0) [[unlikely]] {
        PRINT_WARNING("REWRITE failed: cannot rename shadow file");
        close(new_read_fh);
        return;
    }
    // Exclusive lock only for the in-memory swap (mapping table + read fd)
    int old_read_fh;
    {
        std::unique_lock<std::shared_mutex> write_lock(mapping_table_mutex[iNum]);
        new_mapping_table_entry.has_rewrite = std::move(mapping_table[iNum].has_rewrite);
        mapping_table[iNum] = std::move(new_mapping_table_entry);
        old_read_fh = virtual_file_read_fh[iNum];
        virtual_file_read_fh[iNum] = new_read_fh;
    }
    if (old_read_fh > 0) close(old_read_fh);
}

std::condition_variable_any inline_rewrite_cv;
std::shared_mutex rewrite_queue_mutex;
std::deque<rewrite_req_struct> rewrite_queue;

// Compute the sector-aligned byte range [io_off, io_off+io_size) inside the virtual
// file that the logical range [offset, offset+size) maps to. This mirrors the range
// math in internal_read: a logical range may straddle several groups that are not
// contiguous in the virtual file (build_virtual_file sector-aligns each group), so the
// covered virtual range can exceed `size`. Acquires mapping_table_mutex[iNum] itself,
// so the caller must NOT already hold it. Returns false on failure.
static inline bool logical_to_virtual_offset(INUM_TYPE iNum, off_t offset, size_t size, off_t &io_off, off_t &io_size){
    std::shared_lock<std::shared_mutex> read_lock(mapping_table_mutex[iNum]);
    // find first block group index
    GROUP_IDX_TYPE start_group_idx = mapping_table[iNum].group_idx[offset / CHUNK_SIZE];
    while (true) {
        off_t cur_group_offset = mapping_table[iNum].group_logical_offset[start_group_idx];
        if (cur_group_offset > offset)
            start_group_idx--;
        else if(cur_group_offset + (off_t)mapping_table[iNum].group_pos[start_group_idx]->length <= offset)
            start_group_idx++;
        else break;
        if (start_group_idx < 0 || start_group_idx >= mapping_table[iNum].group_pos.size()) return false;   // It should not happen
    }
    // find need to read range
    off_t end_off = offset + size;
    off_t front_gap = offset - mapping_table[iNum].group_logical_offset[start_group_idx];
    io_off = (mapping_table[iNum].group_virtual_offset[start_group_idx] + front_gap) / SECTOR_SIZE * SECTOR_SIZE;
    GROUP_IDX_TYPE cur_group_idx = start_group_idx;
    while(cur_group_idx < mapping_table[iNum].group_logical_offset.size() &&
                mapping_table[iNum].group_logical_offset[cur_group_idx] < end_off)
        cur_group_idx++;
    cur_group_idx -= 1;
    off_t end_gap = mapping_table[iNum].group_logical_offset[cur_group_idx] + mapping_table[iNum].group_pos[cur_group_idx]->length - end_off;
    if (end_gap < 0)
        end_gap = 0;
    if (cur_group_idx > mapping_table[iNum].completed_link){
        PRINT_WARNING("[warning] trying to read unreferenced group, group_idx: " << start_group_idx);
        return false;
    }
    io_size = mapping_table[iNum].group_virtual_offset[cur_group_idx] + (off_t)mapping_table[iNum].group_pos[cur_group_idx]->length - end_gap - io_off;
    io_size = (io_size + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE;  // allign with page
    return true;
}

alignas(4096) char rewrite_buffer[ONESHOT_REWRITE_SIZE];

//remap rewrite
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
        
        // Group requests by iNum. Deduplicate by logical_offset only, ignoring buffer pointer.
        // char* points into local_batch's stable storage; deque iterators/references remain
        // valid as long as we don't push/pop on local_batch itself.
        std::map<INUM_TYPE, std::set<std::pair<off_t, off_t>, RewriteChunkCmp>> rewrite_map;
        /*for (auto& req : local_batch) {
            if (!running) [[unlikely]] break;
            off_t src_off;
            #ifdef REWRITE_DEDUP
            char tmp_fp[SHA_DIGEST_LENGTH];
            SHA1((const unsigned char *)req.buffer, SECTOR_SIZE, (unsigned char *)tmp_fp);
            FP_TYPE fp(tmp_fp, SHA_DIGEST_LENGTH);
            // check FP exist in rewrite file
            auto fp_store_iter = rewrite_fp_store.find(fp);
            if (fp_store_iter == rewrite_fp_store.end()){   // not found
                rewrite_fp_store[fp] = rewrite_file_size;
                pwrite(rewrite_fh, req.buffer, SECTOR_SIZE, rewrite_file_size);
                real_rewrite_size += SECTOR_SIZE;
                src_off = rewrite_file_size;
                rewrite_file_size += SECTOR_SIZE;
            }
            else src_off = fp_store_iter->second;
            #else
            pwrite(rewrite_write_fh, req.buffer, SECTOR_SIZE, rewrite_file_size);
            real_rewrite_size += SECTOR_SIZE;
            src_off = rewrite_file_size;
            rewrite_file_size += SECTOR_SIZE;
            #endif
            rewrite_map[req.iNum].insert({req.logical_offset, src_off});
        }
        */
        int rewrite_buffer_size = 0;
        off_t rewrite_file_cursor = rewrite_file_size;
        for (auto& req : local_batch){
            if (!running) [[unlikely]] break;

            // flash buffer
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

            rewrite_map[req.iNum].insert({req.logical_offset, rewrite_file_cursor});
            rewrite_file_cursor += SECTOR_SIZE;
        }
        if (rewrite_buffer_size != 0){
            int ret = pwrite(rewrite_write_fh, rewrite_buffer, rewrite_buffer_size, rewrite_file_size);
            if (ret != rewrite_buffer_size) PRINT_WARNING("Can not flush rewrite buffer!!!");
            real_rewrite_size += rewrite_buffer_size;
            rewrite_file_size += rewrite_buffer_size;
        }
        int result = posix_fadvise(rewrite_read_fh, 0, 0, POSIX_FADV_RANDOM);        // remind kernel that this file is random I/O
        if (result != 0) PRINT_WARNING("Can not set POSIX_FADV_RANDOM");
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
            // These pages are now served from the rewrite file, so the copies still
            // cached in the (old) virtual file are redundant. Drop them from the page
            // cache to avoid keeping two copies of the same data in memory.
            // (logical_to_virtual_offset takes mapping_table_mutex[iNum] internally,
            //  so do NOT hold it here.)
            //int read_fh = virtual_file_read_fh[iNum];
            //if (read_fh > 0){
            //    for (auto &[logical_offset, src_off]: chunks){
            //        off_t io_off, io_size;
            //        if (!logical_to_virtual_offset(iNum, logical_offset, SECTOR_SIZE, io_off, io_size)) {
            //            PRINT_WARNING("Warning: Can not find out don't need area");
            //            continue;
            //        }
            //        int ret = posix_fadvise(read_fh, io_off, io_size, POSIX_FADV_DONTNEED);
            //        if (ret != 0) PRINT_WARNING("posix_fadvise failed");
            //    }
            //}
            //else PRINT_WARNING("Warning: Can not set POSIX_FADV_DONTNEED, lack of fh");
        }
    }
}

// inline rewrite worker
void inline_rewrite_worker(){
    rewrite_write_fh = open(BACKEND CHUNK_STORE REWRITE_FILE_PATH, O_RDWR | O_CREAT, 0666);
    rewrite_read_fh = open(BACKEND CHUNK_STORE REWRITE_FILE_PATH, O_RDONLY | O_DIRECT, 0666);
    INUM_TYPE rewrite_file_iNum = get_inum(REWRITE_FILE_PATH);

    if (rewrite_write_fh == -1){
        PRINT_WARNING("Critical Error: Can not open rewrite write file handler in inline rewrite worker");
        return;
    }
    if (rewrite_read_fh == -1){
        PRINT_WARNING("Critical Error: Can not open rewrite read file handler in inline rewrite worker");
        return;
    }
    while (running){
        std::deque<rewrite_req_struct> local_batch;
        {
            std::unique_lock<std::shared_mutex> lock(rewrite_queue_mutex);
            inline_rewrite_cv.wait(lock, []{ return rewrite_queue.size() > 1024 || !running; });
            if (!running) break;
            std::swap(local_batch, rewrite_queue);
        }
        
        // Group requests by iNum. Deduplicate by logical_offset only, ignoring buffer pointer.
        // char* points into local_batch's stable storage; deque iterators/references remain
        // valid as long as we don't push/pop on local_batch itself.
        std::map<INUM_TYPE, std::set<std::pair<off_t, off_t>, RewriteChunkCmp>> rewrite_map;
        for (auto& req : local_batch) {
            if (!running) [[unlikely]] break;
            off_t src_off;
            #ifdef REWRITE_DEDUP
            char tmp_fp[SHA_DIGEST_LENGTH];
            SHA1((const unsigned char *)req.buffer, SECTOR_SIZE, (unsigned char *)tmp_fp);
            FP_TYPE fp(tmp_fp, SHA_DIGEST_LENGTH);
            // check FP exist in rewrite file
            auto fp_store_iter = rewrite_fp_store.find(fp);
            if (fp_store_iter == rewrite_fp_store.end()){   // not found
                rewrite_fp_store[fp] = rewrite_file_size;
                pwrite(rewrite_fh, req.buffer, SECTOR_SIZE, rewrite_file_size);
                real_rewrite_size += SECTOR_SIZE;
                src_off = rewrite_file_size;
                rewrite_file_size += SECTOR_SIZE;
            }
            else src_off = fp_store_iter->second;
            #else
            pwrite(rewrite_write_fh, req.buffer, SECTOR_SIZE, rewrite_file_size);
            real_rewrite_size += SECTOR_SIZE;
            src_off = rewrite_file_size;
            rewrite_file_size += SECTOR_SIZE;
            #endif
            rewrite_map[req.iNum].insert({req.logical_offset, src_off});
        }
        
        std::vector<std::thread> threads;
        for (auto& [iNum, chunks] : rewrite_map){
            if (!running) [[unlikely]] break;
            max_inline_rewrite_chunks = std::max(max_inline_rewrite_chunks, (uint64_t)chunks.size());
            total_rewrite_size += chunks.size() * SECTOR_SIZE;
            threads.emplace_back([&, iNum=iNum]{ 
                rewrite_handler(iNum, chunks, rewrite_file_iNum);
            });
        }
        sleep(5);
        for (auto& t : threads)
            t.join();
    }
}

//out-of-line rewrite wrapper
void rewrite(){
    int rewrite_fh = open(BACKEND CHUNK_STORE REWRITE_FILE_PATH, O_RDWR | O_CREAT, 0666);
    INUM_TYPE rewrite_file_iNum = get_inum(REWRITE_FILE_PATH);

    if (rewrite_fh == -1){
        PRINT_WARNING("Critical Error: Can not open rewrite file handler in inline rewrite worker");
        return;
    }
    std::deque<rewrite_req_struct> local_batch;
    {
        std::unique_lock<std::shared_mutex> lock(rewrite_queue_mutex);
        if (rewrite_queue.empty()) [[unlikely]] {
            close(rewrite_fh);
            PRINT_WARNING("Rewrite queue is empty!!");
            return;
        }
        std::swap(local_batch, rewrite_queue);
    }
    
    // Group requests by iNum. Deduplicate by logical_offset only, ignoring buffer pointer.
    // char* points into local_batch's stable storage; deque iterators/references remain
    // valid as long as we don't push/pop on local_batch itself.
    std::map<INUM_TYPE, std::set<std::pair<off_t, off_t>, RewriteChunkCmp>> rewrite_map;
    for (auto& req : local_batch) {
        if (!running) [[unlikely]] break;
        off_t src_off;
        #ifdef REWRITE_DEDUP
        char tmp_fp[SHA_DIGEST_LENGTH];
        SHA1((const unsigned char *)req.buffer, SECTOR_SIZE, (unsigned char *)tmp_fp);
        FP_TYPE fp(tmp_fp, SHA_DIGEST_LENGTH);
        // check FP exist in rewrite file
        auto fp_store_iter = rewrite_fp_store.find(fp);
        if (fp_store_iter == rewrite_fp_store.end()){   // not found
            rewrite_fp_store[fp] = rewrite_file_size;
            pwrite(rewrite_fh, req.buffer, SECTOR_SIZE, rewrite_file_size);
            real_rewrite_size += SECTOR_SIZE;
            src_off = rewrite_file_size;
            rewrite_file_size += SECTOR_SIZE;
        }
        else src_off = fp_store_iter->second;
        #else
        pwrite(rewrite_fh, req.buffer, SECTOR_SIZE, rewrite_file_size);
        real_rewrite_size += SECTOR_SIZE;
        src_off = rewrite_file_size;
        rewrite_file_size += SECTOR_SIZE;
        #endif
        rewrite_map[req.iNum].insert({req.logical_offset, src_off});
    }
    
    std::vector<std::thread> threads;
    for (auto& [iNum, chunks] : rewrite_map){
        if (!running) [[unlikely]] break;
        max_inline_rewrite_chunks = std::max(max_inline_rewrite_chunks, (uint64_t)chunks.size());
        total_rewrite_size += chunks.size() * SECTOR_SIZE;
        threads.emplace_back([&, iNum=iNum]{ 
            rewrite_handler(iNum, chunks, rewrite_file_iNum);
        });
    }
    for (auto& t : threads)
        t.join();
}
