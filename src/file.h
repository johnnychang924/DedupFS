#include <fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <unordered_map>
#include <map>
#include <openssl/sha.h>
#include <string>
#include <set>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cmath>
#include <mutex>
#include <shared_mutex>
#include "def.h"
#include "fastcdc.h"

PATH_TYPE iNum_to_path[MAX_INODE_NUM];
std::unordered_map<PATH_TYPE, INUM_TYPE> path_to_iNum;
std::set<INUM_TYPE> free_iNum;
std::unordered_map<FP_TYPE, group_addr *> fp_store;
std::set<FILE_HANDLER_INDEX_TYPE> free_file_handler;
file_handler_data file_handler[MAX_FILE_HANDLER];   // get iNum by file handler (faster than get by file path)
mapping_table_entry mapping_table[MAX_INODE_NUM];

std::shared_mutex create_file_mutex;    // the lock for create new file
std::shared_mutex fp_store_mutex;       // the lock for access fp_store
std::shared_mutex file_handler_mutex;   // the lock for allocate file handler and free file handler
std::shared_mutex status_record_mutex;  // the lock for recording file system status
std::shared_mutex chunker_mutex;        // the lock for access chunker
std::shared_mutex read_record_mutex;    // the lock for record host/fuse/ssd read size

unsigned long total_write_size = 0;     // total size of writed file in this file system
unsigned long total_dedup_size = 0;     // total size of writed file in this file system after deduplication

uint64_t host_read_size = 0;
uint64_t fuse_read_size = 0;
uint64_t ssd_read_size = 0;

fcdc_ctx cdc, *ctx;

inline INUM_TYPE get_inum(PATH_TYPE path_str){
    std::shared_lock<std::shared_mutex> shared_create_file_lock(create_file_mutex);     // make sure nobody is creating new file at the same time
    auto it = path_to_iNum.find(path_str);
    shared_create_file_lock.unlock();
    if (it != path_to_iNum.end()){
        return it->second;
    }
    else {
        std::unique_lock<std::shared_mutex> unique_create_file_lock(create_file_mutex); // lock for creating new file
        if (free_iNum.empty()){
            PRINT_WARNING("run out of iNum");
            return -1;
        }
        INUM_TYPE new_iNum = *free_iNum.begin();
        free_iNum.erase(free_iNum.begin());
        path_to_iNum[path_str] = new_iNum;
        iNum_to_path[new_iNum] = path_str;
        return new_iNum;
    }
}

inline PATH_TYPE get_path(INUM_TYPE iNum){
    std::shared_lock<std::shared_mutex> shared_create_file_lock(create_file_mutex);      // make sure nobody is creating new file at the same time
    return iNum_to_path[iNum];
}

inline FILE_HANDLER_INDEX_TYPE get_free_file_handler(){
    std::unique_lock<std::shared_mutex> unique_file_handler_lock(file_handler_mutex);   // lock for allocating new file handler
    if (free_file_handler.empty()){
        PRINT_WARNING("dedupfs: run out of file handlers");
        return -1;
    }
    FILE_HANDLER_INDEX_TYPE new_file_handler_index = *free_file_handler.begin();
    free_file_handler.erase(free_file_handler.begin());
    return new_file_handler_index;
}

inline void release_file_handler(FILE_HANDLER_INDEX_TYPE file_handler_index){
    if (file_handler_index < 0 || file_handler_index >= MAX_FILE_HANDLER) return;
    std::unique_lock<std::shared_mutex> unique_file_handler_lock(file_handler_mutex);    // lock for freeing file handler
    free_file_handler.insert(file_handler_index);
}

inline void init_file_handler(const char *path, FILE_HANDLER_INDEX_TYPE file_handler_index, int real_file_handler, char mode){
    PATH_TYPE path_str(path);
    INUM_TYPE iNum = get_inum(path_str);
    file_handler[file_handler_index] = {
        .iNum = iNum,
        .fh = real_file_handler,
        .mode = mode,
    };
    if (mode == 'w'){
        file_handler[file_handler_index].write_buf = {
            .start_byte = 0,
            .byte_cnt = 0,
            .content = new char[MAX_GROUP_SIZE],
        };
    }
}

static int dedupfs_getattr(const char *path, struct stat *stbuf) {
    DEBUG_MESSAGE("[getattr]" << path);
    int res;
    char full_path[1024];
    PATH_TYPE path_str(path);
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    res = lstat(full_path, stbuf);
    if (res == -1) {
        return -errno;
    }
    std::shared_lock<std::shared_mutex> shared_create_file_lock(create_file_mutex);     // make sure nobody is creating new file at the same time
    auto it = path_to_iNum.find(path_str);
    if (it != path_to_iNum.end()){
        INUM_TYPE iNum = it->second;
        stbuf->st_size = mapping_table[iNum].logical_size_for_host;
    }
    shared_create_file_lock.unlock();
    return 0;
}

static int dedupfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    int real_file_handler;
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    DEBUG_MESSAGE("[create]" << path);
    real_file_handler = creat(full_path, mode);
    if (real_file_handler == -1) return -errno;
    fi->fh = get_free_file_handler();
    if (fi->fh == (FILE_HANDLER_INDEX_TYPE)-1) return -errno;
    init_file_handler(path, fi->fh, real_file_handler, 'w');
    return 0;
}

static int dedupfs_open(const char *path, struct fuse_file_info *fi) {
    DEBUG_MESSAGE("[open]" << path);
    int real_file_handler;
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    real_file_handler = open(full_path, fi->flags);
    if (real_file_handler == -1)
        return -errno;
    fi->fh = get_free_file_handler();
    if (fi->fh == (FILE_HANDLER_INDEX_TYPE)-1)
        return -errno;
    char mode = fi->flags & (O_WRONLY | O_RDWR) ? 'w' : 'r';
    DEBUG_MESSAGE("mode: " << mode);
    init_file_handler(path, fi->fh, real_file_handler, mode);
    return 0;
}

static int cdcfs_release(const char *path, struct fuse_file_info *fi) {
    int res;
    DEBUG_MESSAGE("[release]" << path);

    INUM_TYPE iNum = file_handler[fi->fh].iNum;
    buffer_entry *file_buffer = &file_handler[fi->fh].write_buf;

    // write back file buffer
    int write_back_ptr = 0;
    while (write_back_ptr < file_buffer->byte_cnt){
        DEBUG_MESSAGE("  start write back file buffer");
        // not implement content chunking yet, use fixed sized
        //int cut_pos = std::min(file_buffer->byte_cnt, (uint16_t)4096);
        //int cut_pos = file_buffer->byte_cnt;
        int cut_pos = cut((const uint8_t*)file_buffer->content + write_back_ptr, file_buffer->byte_cnt - write_back_ptr, ctx->mi, ctx->ma, ctx->ns,
                      ctx->mask_s, ctx->mask_l);

        #ifdef CAFTL
        cut_pos = std::min(file_buffer->byte_cnt, (uint16_t)BLOCK_SIZE); // use fixed chunking
        #endif
        DEBUG_MESSAGE("    cut pos: " << cut_pos << " actual_size_in_disk: " << mapping_table[iNum].actual_size_in_disk);

        std::unique_lock<std::shared_mutex> unique_status_record_lock(status_record_mutex);
        total_write_size += cut_pos;
        unique_status_record_lock.unlock();

        char cur_fp[SHA_DIGEST_LENGTH];
        SHA1((const unsigned char *)file_buffer->content + write_back_ptr, cut_pos, (unsigned char *)cur_fp);
        FP_TYPE new_fp(cur_fp, SHA_DIGEST_LENGTH);

        #ifdef NODEDUPE
            group_addr *new_group_addr = new group_addr;
            new_group_addr->iNum = iNum;
            new_group_addr->ref_times = 1;
            new_group_addr->start_byte = mapping_table[iNum].actual_size_in_disk;
            new_group_addr->group_length = cut_pos;
            int res = pwrite(file_handler[fi->fh].fh, file_buffer->content + write_back_ptr, cut_pos, mapping_table[iNum].actual_size_in_disk);
            if (res == -1){
                PRINT_WARNING("write back to disk failed!!");
                delete new_group_addr;
                return -errno;
            }
            int blk_count = std::ceil((float)cut_pos / BLOCK_SIZE);
            mapping_table[iNum].actual_size_in_disk += cut_pos;
            mapping_table[iNum].group_pos.push_back(new_group_addr);
            mapping_table[iNum].group_offset.push_back(file_buffer->start_byte + write_back_ptr);
            for(int i = 0; i < blk_count; i++){
                mapping_table[iNum].group_idx.push_back(mapping_table[iNum].group_pos.size() - 1);
            }
            std::unique_lock<std::shared_mutex> unique_fp_store_lock(fp_store_mutex);
            fp_store[new_fp] = new_group_addr;
            unique_fp_store_lock.unlock();
        #endif
        #ifndef NODEDUPE
        std::unique_lock<std::shared_mutex> shared_fp_store_lock(fp_store_mutex);
        auto fp_store_iter = fp_store.find(new_fp);
        shared_fp_store_lock.unlock();
        if (fp_store_iter != fp_store.end()){   // found
            DEBUG_MESSAGE("    found duplicate group!!");
            unique_status_record_lock.lock();
            total_dedup_size += cut_pos;
            unique_status_record_lock.unlock();
            mapping_table[iNum].group_pos.push_back(fp_store_iter->second);
            fp_store_iter->second->ref_times += 1;
            mapping_table[iNum].group_offset.push_back(file_buffer->start_byte + write_back_ptr);
            int blk_count = std::ceil((float)cut_pos / BLOCK_SIZE);
            for(int i = 0; i < blk_count; i++){
                mapping_table[iNum].group_idx.push_back(mapping_table[iNum].group_pos.size() - 1);
            }
        }
        else{                                   // not found
            group_addr *new_group_addr = new group_addr;
            new_group_addr->iNum = iNum;
            new_group_addr->ref_times = 1;
            new_group_addr->start_byte = mapping_table[iNum].actual_size_in_disk;
            new_group_addr->group_length = cut_pos;
            int res = pwrite(file_handler[fi->fh].fh, file_buffer->content + write_back_ptr, cut_pos, mapping_table[iNum].actual_size_in_disk);
            if (res == -1){
                PRINT_WARNING("write back to disk failed!!");
                delete new_group_addr;
                return -errno;
            }
            int blk_count = std::ceil((float)cut_pos / BLOCK_SIZE);
            mapping_table[iNum].actual_size_in_disk += cut_pos;
            mapping_table[iNum].group_pos.push_back(new_group_addr);
            mapping_table[iNum].group_offset.push_back(file_buffer->start_byte + write_back_ptr);
            for(int i = 0; i < blk_count; i++){
                mapping_table[iNum].group_idx.push_back(mapping_table[iNum].group_pos.size() - 1);
            }
            std::unique_lock<std::shared_mutex> unique_fp_store_lock(fp_store_mutex);
            fp_store[new_fp] = new_group_addr;
            unique_fp_store_lock.unlock();
        }
        #endif

        write_back_ptr += cut_pos;
    }
    if (file_buffer->content != NULL){
        free(file_buffer->content);
        file_buffer->content = NULL;
    }

    res = close(file_handler[fi->fh].fh);
    if (res == -1) {
        return -errno;
    }
    release_file_handler(fi->fh);
    return 0;
}

static int cdcfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    DEBUG_MESSAGE("[read]" << path << " offset: " << offset << " size: " << size);
    struct interval {off_t start; off_t end;};

    // find first block group index
    INUM_TYPE iNum = file_handler[fi->fh].iNum;

    std::unique_lock<std::shared_mutex> unique_read_record_lock(read_record_mutex);
    host_read_size += std::abs((off_t)std::min(offset + size, mapping_table[iNum].logical_size_for_host) - offset);
    unique_read_record_lock.unlock();

    #ifdef READ_REQ_OUTPUT_PATH
        rd_req[rd_req_count++] = {iNum, offset, size};
    #endif
    uint32_t blk_num = offset / BLOCK_SIZE;
    unsigned long start_group_idx;
    if (blk_num < mapping_table[iNum].group_idx.size() && (uint32_t)mapping_table[iNum].group_idx[blk_num] < mapping_table[iNum].group_pos.size()){
        start_group_idx = mapping_table[iNum].group_idx[blk_num];
    }
    else{
        start_group_idx = mapping_table[iNum].group_pos.size()-1;
    }
    if (mapping_table[iNum].group_pos.size() == 0 || size == 0) return 0;

    while (true) {
        off_t cur_group_offset = mapping_table[iNum].group_offset[start_group_idx];
        if (cur_group_offset > offset)
            start_group_idx--;
        else if(cur_group_offset + mapping_table[iNum].group_pos[start_group_idx]->group_length <= offset)
            start_group_idx++;
        else break;
        if (start_group_idx < 0 || start_group_idx >= mapping_table[iNum].group_pos.size()) return 0;
    }
    DEBUG_MESSAGE("  start block: " << start_group_idx);
    
    // seperate each block group by iNum
    std::map<INUM_TYPE, std::vector<group_addr *>> group_idx_of_inode;
    int less = size + (offset - mapping_table[iNum].group_offset[start_group_idx]);
    unsigned long cur_group_idx = start_group_idx;
    while(less > 0 && cur_group_idx < mapping_table[iNum].group_pos.size()) {
        group_addr *cur_group = mapping_table[iNum].group_pos[cur_group_idx];
        INUM_TYPE cur_iNum = cur_group->iNum;
        if (group_idx_of_inode.find(cur_iNum) == group_idx_of_inode.end()){
            group_idx_of_inode[cur_iNum] = std::vector<group_addr *>();
        }
        group_idx_of_inode[cur_iNum].push_back(cur_group);
        less -= cur_group->group_length;
        cur_group_idx++;
    }
    unsigned long end_group_idx = cur_group_idx;

    DEBUG_MESSAGE("  end block: " << end_group_idx);

    // analyze need to read block group part
    std::map<group_addr *, interval> inter_group_interval;
    for (cur_group_idx = start_group_idx; cur_group_idx < end_group_idx; cur_group_idx++) {
        group_addr *cur_group = mapping_table[iNum].group_pos[cur_group_idx];
        off_t cur_group_offset = mapping_table[iNum].group_offset[cur_group_idx];
        off_t inter_group_start = cur_group_offset > offset ? 0 : offset - cur_group_offset;
        off_t inter_group_end = cur_group_offset + (size_t)cur_group->group_length < offset + size 
                ? cur_group->group_length : offset + size - cur_group_offset;
        if (inter_group_interval.find(cur_group) == inter_group_interval.end()){
            inter_group_interval[cur_group] = { inter_group_start, inter_group_end };
        }
        else{
            inter_group_interval[cur_group].start = std::min(inter_group_interval[cur_group].start, inter_group_start);
            inter_group_interval[cur_group].end = std::max(inter_group_interval[cur_group].end, inter_group_end);
        }
    }

    #ifdef DEBUG
    for (auto it = group_idx_of_inode.begin(); it!= group_idx_of_inode.end(); ++it){
        DEBUG_MESSAGE("  INum: " << it->first);
        for (auto it2 = it->second.begin(); it2!= it->second.end(); ++it2){
            DEBUG_MESSAGE("    - Start Byte: " << inter_group_interval[*it2].start);
            DEBUG_MESSAGE("    - End Byte: " << inter_group_interval[*it2].end);
            DEBUG_MESSAGE("    - Group address: " << (*it2)->start_byte << " - " << (*it2)->group_length);
        }
    }
    #endif

    // read each block group into temp buffer
    char tmp_buf[size + MAX_GROUP_SIZE];        // in some case we will read some useless data, so add MAX_GROUP_SIZE to avoid segmentation fault.
    std::map<group_addr *, interval> tmp_buf_map; // map group address contents and its start byte in temp buffer
    off_t tmp_buf_len = 0;
    for (auto it = group_idx_of_inode.begin(); it!= group_idx_of_inode.end(); ++it) {
        INUM_TYPE cur_iNum = it->first;
        DEBUG_MESSAGE("  reading iNum: " << cur_iNum);
        uint64_t fh;
        if (cur_iNum == iNum) fh = file_handler[fi->fh].fh;
        else{
            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, iNum_to_path[cur_iNum].c_str());
            DEBUG_MESSAGE("  tring to open: " << full_path);
            fh = open(full_path, O_RDONLY | O_DIRECT);
            if (fh == -1UL) {
                DEBUG_MESSAGE("  open failed: " << strerror(errno));
                return -errno;
            }
        }
        // sort group index by each group start bytes
        std::sort(it->second.begin(), it->second.end(), [](group_addr *group1, group_addr *group2) {
            return group1->start_byte < group2->start_byte;
        });
        for (uint32_t i = 0; i < it->second.size(); ++i){
            group_addr *cur_group = it->second[i];
            if (tmp_buf_map.find(cur_group) != tmp_buf_map.end()) continue; // have been read this block before
            size_t inter_group_len = inter_group_interval[cur_group].end - inter_group_interval[cur_group].start;
            tmp_buf_map[cur_group] = {tmp_buf_len, tmp_buf_len + (off_t)inter_group_len};
            tmp_buf_len += inter_group_len;
            // create a big continuous io
            uint32_t j = i;
            off_t io_start = inter_group_interval[cur_group].start + cur_group->start_byte;
            size_t io_len = inter_group_len;
            while (++j < it->second.size()){
                group_addr *next_group = it->second[j];
                if (tmp_buf_map.find(next_group) != tmp_buf_map.end()) continue; // duplicate block ignore;
                // next block is continuous
                if (inter_group_interval[cur_group].end + cur_group->start_byte == inter_group_interval[next_group].start + next_group->start_byte){
                    inter_group_len = inter_group_interval[next_group].end - inter_group_interval[next_group].start;
                    tmp_buf_map[next_group] = {tmp_buf_len, tmp_buf_len + (off_t)inter_group_len};
                    tmp_buf_len += inter_group_len;
                    io_len += inter_group_len;
                    cur_group = next_group;
                    i++;
                }
                // next block is not continuous
                else break;
            }
            DEBUG_MESSAGE("  reading " << "(" << (int)cur_iNum << ")" << " from " << io_start << " until " << io_len);
            #ifdef SECTOR_SIZE
            off_t f2fs_io_start = io_start - io_start % SECTOR_SIZE;
            size_t f2fs_io_len = io_len + io_start % SECTOR_SIZE;
            f2fs_io_len = (f2fs_io_len + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE;
            char f2fs_buf[f2fs_io_len];
            int res = pread(fh, f2fs_buf, f2fs_io_len, f2fs_io_start);
            memcpy(tmp_buf + tmp_buf_len - io_len, f2fs_buf + io_start % SECTOR_SIZE, io_len);
            #else
            int res = pread(fh, tmp_buf + tmp_buf_len - io_len, io_len, io_start);
            #endif
            unique_read_record_lock.lock();
            fuse_read_size += res;
            ssd_read_size += (io_start + res + SSD_ONESHOT - (io_start + res - 1) % SSD_ONESHOT - 1) - (io_start - io_start % SSD_ONESHOT);
            unique_read_record_lock.unlock();
            if (res == -1) {
                PRINT_WARNING("read failed: " << io_start << "(offset) " << io_len << "(size) " << strerror(errno));
                #ifdef SECTOR_SIZE
                PRINT_WARNING("read failed(f2fs): " << f2fs_io_start << "(offset) " << f2fs_io_len << "(size)");
                #endif
                PRINT_WARNING("");
                if (cur_iNum == iNum) close(fh);
                return -1;
            }
        }
        if (cur_iNum != iNum) close(fh);
    }

    // fill return buffer
    size_t read_size = 0;
    for (cur_group_idx = start_group_idx; cur_group_idx < end_group_idx; cur_group_idx++) {
        group_addr *cur_group = mapping_table[iNum].group_pos[cur_group_idx];
        off_t cur_group_offset = mapping_table[iNum].group_offset[cur_group_idx];
        off_t cur_inter_group_offset = cur_group_offset > offset ? 0 : offset - cur_group_offset;
        size_t cur_inter_group_end = cur_group_offset + (size_t)cur_group->group_length < offset + size 
                ? cur_group->group_length : offset + size - cur_group_offset;
        off_t in_tmp_buf_offset = tmp_buf_map[cur_group].start + (cur_inter_group_offset - inter_group_interval[cur_group].start);
        size_t in_tmp_buf_end = tmp_buf_map[cur_group].end - (inter_group_interval[cur_group].end - cur_inter_group_end);
        DEBUG_MESSAGE("  filling group: " << cur_group_idx << " from buffer: " << in_tmp_buf_offset << " to " << in_tmp_buf_end);
        memcpy(buf + read_size, tmp_buf + in_tmp_buf_offset, in_tmp_buf_end - in_tmp_buf_offset);
        read_size += in_tmp_buf_end - in_tmp_buf_offset;
    }
    return read_size;
}

static int cdcfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    DEBUG_MESSAGE("[write]" << path << " offset: " << offset << " size: " << size);

    INUM_TYPE iNum = file_handler[fi->fh].iNum;
    buffer_entry *in_buffer_data = &file_handler[fi->fh].write_buf;

    if (in_buffer_data->start_byte > 0 && in_buffer_data->start_byte + in_buffer_data->byte_cnt != offset) {     // file buffer is not empty and current write is not continous.
        PRINT_WARNING("write: detect not continous write in write buffer");
        return -errno;
    }

    if (offset < (long int)mapping_table[iNum].actual_size_in_disk + in_buffer_data->byte_cnt) {
        PRINT_WARNING("write: currently not support data update.");
        return -errno;
    }

    if (in_buffer_data->byte_cnt == 0) in_buffer_data->start_byte = offset;

    size_t less_size = size;
    char * cur_buf_ptr = (char *)buf;
    mapping_table[iNum].logical_size_for_host += size;
    while (less_size > 0) {
        bool can_fill_buffer = in_buffer_data->byte_cnt + less_size >= MAX_GROUP_SIZE;
        if (can_fill_buffer){
            DEBUG_MESSAGE("  start write back file buffer");
            int write_into_buffer_size = MAX_GROUP_SIZE - in_buffer_data->byte_cnt;
            memcpy(in_buffer_data->content + in_buffer_data->byte_cnt, cur_buf_ptr, write_into_buffer_size);
            less_size -= write_into_buffer_size;
            cur_buf_ptr += write_into_buffer_size;
            int cut_pos = cut((const uint8_t*)in_buffer_data->content, MAX_GROUP_SIZE, ctx->mi, ctx->ma, ctx->ns,
                      ctx->mask_s, ctx->mask_l);
            #ifdef CAFTL
            cut_pos = BLOCK_SIZE; // use fixed chunking
            #endif
            DEBUG_MESSAGE("    cut pos: " << cut_pos << " byte cnt: " << in_buffer_data->byte_cnt);
            std::unique_lock<std::shared_mutex> unique_status_record_lock(status_record_mutex);
            total_write_size += cut_pos;
            unique_status_record_lock.unlock();
            // hashing
            char cur_fp[SHA_DIGEST_LENGTH];
            SHA1((const unsigned char *)in_buffer_data->content, cut_pos, (unsigned char *)cur_fp);
            FP_TYPE new_fp(cur_fp, SHA_DIGEST_LENGTH);
            // query fp store
            #ifdef NODEDUPE
                group_addr *new_group_addr = new group_addr;
                new_group_addr->iNum = iNum;
                new_group_addr->ref_times = 1;
                new_group_addr->start_byte = mapping_table[iNum].actual_size_in_disk;
                new_group_addr->group_length = cut_pos;
                int res = pwrite(file_handler[fi->fh].fh, in_buffer_data->content, cut_pos, mapping_table[iNum].actual_size_in_disk);
                if (res == -1){
                    PRINT_WARNING("write: write back to disk failed!!");
                    delete new_group_addr;
                    return -errno;
                }
                mapping_table[iNum].actual_size_in_disk += cut_pos;
                mapping_table[iNum].group_pos.push_back(new_group_addr);
                mapping_table[iNum].group_offset.push_back(in_buffer_data->start_byte);
                for(int i = mapping_table[iNum].group_idx.size(); i <= (in_buffer_data->start_byte + cut_pos) / BLOCK_SIZE; i++){
                    mapping_table[iNum].group_idx.push_back(mapping_table[iNum].group_pos.size() - 1);
                }
                std::unique_lock<std::shared_mutex> unique_fp_store_lock(fp_store_mutex);
                fp_store[new_fp] = new_group_addr;
                unique_fp_store_lock.unlock();
            #endif
            #ifndef NODEDUPE
            std::shared_lock<std::shared_mutex> shared_fp_store_lock(fp_store_mutex);
            auto fp_store_iter = fp_store.find(new_fp);
            shared_fp_store_lock.unlock();
            if (fp_store_iter != fp_store.end()){   // found
                DEBUG_MESSAGE("    found duplicate group!!");
                unique_status_record_lock.lock();
                total_dedup_size += cut_pos;
                unique_status_record_lock.unlock();
                fp_store_iter->second->ref_times += 1;
                mapping_table[iNum].group_pos.push_back(fp_store_iter->second);
                mapping_table[iNum].group_offset.push_back(in_buffer_data->start_byte);
                for(int i = mapping_table[iNum].group_idx.size(); i <= (in_buffer_data->start_byte + cut_pos) / BLOCK_SIZE; i++){
                    mapping_table[iNum].group_idx.push_back(mapping_table[iNum].group_pos.size() - 1);
                }
            }
            else{                                   // not found
                group_addr *new_group_addr = new group_addr;
                new_group_addr->iNum = iNum;
                new_group_addr->ref_times = 1;
                new_group_addr->start_byte = mapping_table[iNum].actual_size_in_disk;
                new_group_addr->group_length = cut_pos;
                int res = pwrite(file_handler[fi->fh].fh, in_buffer_data->content, cut_pos, mapping_table[iNum].actual_size_in_disk);
                if (res == -1){
                    PRINT_WARNING("write: write back to disk failed!!");
                    delete new_group_addr;
                    return -errno;
                }
                mapping_table[iNum].actual_size_in_disk += cut_pos;
                mapping_table[iNum].group_pos.push_back(new_group_addr);
                mapping_table[iNum].group_offset.push_back(in_buffer_data->start_byte);
                for(int i = mapping_table[iNum].group_idx.size(); i <= (in_buffer_data->start_byte + cut_pos) / BLOCK_SIZE; i++){
                    mapping_table[iNum].group_idx.push_back(mapping_table[iNum].group_pos.size() - 1);
                }
                std::unique_lock<std::shared_mutex> unique_fp_store_lock(fp_store_mutex);
                fp_store[new_fp] = new_group_addr;
                unique_fp_store_lock.unlock();
            }
            #endif
            // update buffer
            if (cut_pos < MAX_GROUP_SIZE){
                //memcpy(in_buffer_data->content, in_buffer_data->content + cut_pos, MAX_GROUP_SIZE - cut_pos);
                for (char *i = in_buffer_data->content + cut_pos, *j = in_buffer_data->content; i < in_buffer_data->content + MAX_GROUP_SIZE; i++, j++){
                    *j = *i;
                }
            }
            in_buffer_data->start_byte += cut_pos;
            in_buffer_data->byte_cnt = MAX_GROUP_SIZE - cut_pos;
        }
        else{
            DEBUG_MESSAGE("start fill buffer");
            DEBUG_MESSAGE("in_buffer_data->byte_cnt: " << in_buffer_data->byte_cnt);
            DEBUG_MESSAGE("less_size: " << less_size);
            memcpy(in_buffer_data->content + in_buffer_data->byte_cnt, cur_buf_ptr, less_size);
            DEBUG_MESSAGE("end fill buffer");
            in_buffer_data->byte_cnt += less_size;
            less_size = 0;
        }
    }
    return size;
}
