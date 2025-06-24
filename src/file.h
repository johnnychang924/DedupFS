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
#include <sys/ioctl.h>
#include <linux/fs.h>

// iNumber management
std::set<INUM_TYPE> free_iNum;
PATH_TYPE iNum_to_path[MAX_INODE_NUM];
std::unordered_map<PATH_TYPE, INUM_TYPE> path_to_iNum;
// file handler
std::set<FILE_HANDLER_INDEX_TYPE> free_file_handler;
file_handler_data file_handler[MAX_FILE_HANDLER];   // get iNum by file handler (faster than get by file path)
// fingerprint store
std::unordered_map<FP_TYPE, hash_store_entry> fp_store;
// mapping table
mapping_table_entry mapping_table[MAX_INODE_NUM];
// file system stat record
uint64_t total_write_size = 0;     // total size of writed file in this file system
uint64_t real_write_size = 0;      // total size of writed file in this file system after deduplication
uint64_t host_read_size = 0;
uint64_t fuse_read_size = 0;
// lock
std::shared_mutex create_file_mutex;    // the lock for create new file
std::shared_mutex fp_store_mutex;       // the lock for access fp_store
std::shared_mutex file_handler_mutex;   // the lock for allocate file handler and free file handler
std::shared_mutex chunker_mutex;        // the lock for access chunker
std::shared_mutex write_record_mutex;  // the lock for recording file system status
std::shared_mutex read_record_mutex;    // the lock for record host/fuse/ssd read size
// fastCDC chunker
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

inline void init_file_handler(const char *path, FILE_HANDLER_INDEX_TYPE file_handler_index, int real_file_handler, int chunk_store_file_handler, char mode){
    PATH_TYPE path_str(path);
    INUM_TYPE iNum = get_inum(path_str);
    file_handler[file_handler_index] = {
        .iNum = iNum,
        .fh = real_file_handler,
        .csfh = chunk_store_file_handler,
        .mode = mode,
    };
    if (mode == 'w'){
        file_handler[file_handler_index].write_buf = {
            .start_byte = (off_t)mapping_table[iNum].logical_size,
            .byte_cnt = 0,
            .content = new char[MAX_GROUP_SIZE],
        };
    }
}

static int dedupfs_getattr(const char *path, struct stat *stbuf) {
    DEBUG_MESSAGE("[getattr]" << path);
    if (strcmp(path, CHUNK_STORE) == 0 || strncmp(path, CHUNK_STORE"/", 13) == 0) return -EINVAL;
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
        stbuf->st_size = mapping_table[iNum].logical_size;
        stbuf->st_blocks = (mapping_table[iNum].logical_size + 511) / 512;
    }
    shared_create_file_lock.unlock();
    return 0;
}

static int dedupfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    DEBUG_MESSAGE("[create]" << path);
    int real_file_handler, chunk_store_file_handler;
    char full_path[1024];
    char chunk_store_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    snprintf(chunk_store_path, sizeof(chunk_store_path), "%s%s%s", BACKEND, CHUNK_STORE, path);
    real_file_handler = creat(full_path, mode);
    if (real_file_handler == -1) return -errno;
    chunk_store_file_handler = creat(chunk_store_path, mode);
    if (chunk_store_file_handler == -1) return -errno;
    fi->fh = get_free_file_handler();
    if (fi->fh == (FILE_HANDLER_INDEX_TYPE)-1) return -errno;
    init_file_handler(path, fi->fh, real_file_handler, chunk_store_file_handler, 'w');
    // force real file to shift
    // mapping_table[file_handler[fi->fh].iNum].real_size += 512;
    // ftruncate(chunk_store_file_handler, mapping_table[fi->fh].real_size);
    return 0;
}

static int dedupfs_open(const char *path, struct fuse_file_info *fi) {
    DEBUG_MESSAGE("[open]" << path);
    int real_file_handler, chunk_store_file_handler;
    char full_path[1024];
    char chunk_store_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    snprintf(chunk_store_path, sizeof(chunk_store_path), "%s%s%s", BACKEND, CHUNK_STORE, path);
    real_file_handler = open(full_path, fi->flags);
    if (real_file_handler == -1) return -errno;
    if (fi->flags & (O_WRONLY | O_RDWR)) {      // need to write
        chunk_store_file_handler = open(chunk_store_path, fi->flags);
        if (chunk_store_file_handler == -1) return -errno;
    }
    else chunk_store_file_handler = -1;
    fi->fh = get_free_file_handler();
    if (fi->fh == -1ULL) return -errno;
    char mode = fi->flags & (O_WRONLY | O_RDWR) ? 'w' : 'r';
    DEBUG_MESSAGE("mode: " << mode);
    init_file_handler(path, fi->fh, real_file_handler, chunk_store_file_handler, mode);
    return 0;
}

static int dedupfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
    DEBUG_MESSAGE("[read]" << path << " offset: " << offset << " size: " << size);
    INUM_TYPE iNum = file_handler[fi->fh].iNum;
    if ((size_t)offset > mapping_table[iNum].logical_size || size == 0) return 0;
    // find first block group index
    GROUP_IDX_TYPE start_group_idx = mapping_table[iNum].group_idx[offset / CHUNK_SIZE];
    while (true) {
        off_t cur_group_offset = mapping_table[iNum].group_logical_offset[start_group_idx];
        if (cur_group_offset > offset)
            start_group_idx--;
        else if(cur_group_offset + (off_t)mapping_table[iNum].group_pos[start_group_idx].length <= offset)
            start_group_idx++;
        else break;
        if (start_group_idx < 0 || start_group_idx >= mapping_table[iNum].group_pos.size()) return 0;   // It should not happen
    }
    DEBUG_MESSAGE("  start block: " << start_group_idx);
    // find need to read range
    off_t end_off = offset + size;
    off_t front_gap = offset - mapping_table[iNum].group_logical_offset[start_group_idx];
    off_t io_off = (mapping_table[iNum].group_virtual_offset[start_group_idx] + front_gap) / SECTOR_SIZE * SECTOR_SIZE;
    GROUP_IDX_TYPE cur_group_idx = start_group_idx;
    while(cur_group_idx < mapping_table[iNum].group_logical_offset.size() && 
                mapping_table[iNum].group_logical_offset[cur_group_idx] < end_off)
        cur_group_idx++;
    cur_group_idx -= 1;
    off_t end_gap = mapping_table[iNum].group_logical_offset[cur_group_idx] + mapping_table[iNum].group_pos[cur_group_idx].length - end_off;
    if (end_gap < 0)
        end_gap = 0;
    size_t io_size = mapping_table[iNum].group_virtual_offset[cur_group_idx] + (off_t)mapping_table[iNum].group_pos[cur_group_idx].length - end_gap - io_off;
    io_size = (io_size + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE;  // allign with page
    // read into temp buffer
    char tmp_buf[io_size];
    DEBUG_MESSAGE("  start reading offset->" << io_off << " size->" << io_size);
    int res = pread(file_handler[fi->fh].fh, tmp_buf, io_size, io_off);
    if ((size_t)res != io_size){
        PRINT_WARNING("Can not read enough chunk from virtual file, should read " << io_size << ", but " << res);
    }
    // fill in return buffer
    int less = size;
    char *cur_buf_ptr = buf;
    cur_group_idx = start_group_idx;
    front_gap = offset - mapping_table[iNum].group_logical_offset[cur_group_idx];
    DEBUG_MESSAGE("  filling return buffer");
    while(less > 0){
        size_t cp_size = std::min(mapping_table[iNum].group_pos[cur_group_idx].length - front_gap, (size_t)less);
        off_t tmp_buf_off = mapping_table[iNum].group_virtual_offset[cur_group_idx] - io_off + front_gap;
        DEBUG_MESSAGE("    cur_group->" << cur_group_idx << " front_gap->" << front_gap << " cp_size->" << cp_size << " group_offset->" << mapping_table[iNum].group_virtual_offset[cur_group_idx] << " group_size->" << mapping_table[iNum].group_pos[cur_group_idx].length << " tmp_buffer_offset->" << tmp_buf_off);
        memcpy(cur_buf_ptr, tmp_buf + tmp_buf_off, cp_size);
        less -= cp_size;
        if (cur_group_idx == mapping_table[iNum].group_pos.size()-1) break;
        cur_buf_ptr += cp_size;
        cur_group_idx++;
        front_gap = 0;
    }
    // record fs read information
    std::unique_lock<std::shared_mutex> unique_read_record_lock(read_record_mutex);
    host_read_size += std::abs((off_t)std::min(offset + size, mapping_table[iNum].logical_size) - offset);
    fuse_read_size += io_size;
    unique_read_record_lock.unlock();
    return size - std::max(less, 0);
}

inline int flush_buffer(buffer_entry *buf, INUM_TYPE iNum, int csfh){       // return actual size write into disk
    DEBUG_MESSAGE("  flush buffer: " << iNum << " buf size: " << buf->byte_cnt);
    // chunking
    std::unique_lock<std::shared_mutex> unique_chunker_lock(chunker_mutex);
    int cut_pos = cut((const uint8_t*)buf->content, MAX_GROUP_SIZE, ctx->mi, ctx->ma, ctx->ns,
                      ctx->mask_s, ctx->mask_l);
    unique_chunker_lock.unlock();
    #if defined(CAFTL) || defined(NODEDUPE)
    cut_pos = CHUNK_SIZE;
    #endif
    cut_pos = std::min(cut_pos, (int)buf->byte_cnt);
    // hashing
    auto fp_store_iter = fp_store.end();
    #ifndef NODEDUPE
    char tmp_fp[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)buf->content, cut_pos, (unsigned char *)tmp_fp);
    FP_TYPE fp(tmp_fp, SHA_DIGEST_LENGTH);
    // query fp store
    std::shared_lock<std::shared_mutex> shared_fp_store_lock(fp_store_mutex);
    fp_store_iter = fp_store.find(fp);
    shared_fp_store_lock.unlock();
    #endif
    if (fp_store_iter != fp_store.end()){   // found
        DEBUG_MESSAGE("    found duplicate group!!");
        fp_store_iter->second.ref_times += 1;
        mapping_table[iNum].group_pos.push_back(fp_store_iter->second.address);
    }
    else{   // not found
        #ifdef PENDING
        int pending_size = (buf->start_byte % SECTOR_SIZE) - (mapping_table[iNum].real_size % SECTOR_SIZE);
        if (pending_size < 0)
            pending_size += SECTOR_SIZE;
        if (pending_size != 0){
            mapping_table[iNum].real_size += pending_size;
            ftruncate(csfh, mapping_table[iNum].real_size);
        }
        #else
        int pending_size = 0;
        #endif
        int res = pwrite(csfh, buf->content, cut_pos, mapping_table[iNum].real_size);
        if (res != cut_pos) return -1;
        mapping_table[iNum].group_pos.push_back({iNum, (off_t)mapping_table[iNum].real_size, (size_t)cut_pos});
        mapping_table[iNum].real_size += cut_pos;
        std::unique_lock<std::shared_mutex> unique_fp_store_lock(fp_store_mutex);
        #ifndef NODEDUPE
        fp_store[fp] = {1, mapping_table[iNum].group_pos.back()};
        #endif
        real_write_size += cut_pos + pending_size;    // borrow fp store's lock
        unique_fp_store_lock.unlock();
    }
    mapping_table[iNum].group_logical_offset.push_back(buf->start_byte);
    for(GROUP_IDX_TYPE i = mapping_table[iNum].group_idx.size(); i <= (buf->start_byte + cut_pos) / CHUNK_SIZE; i++)
        mapping_table[iNum].group_idx.push_back(mapping_table[iNum].group_pos.size() - 1);
    if (buf->byte_cnt - cut_pos > 0)
        memcpy(buf->content, buf->content+cut_pos, buf->byte_cnt - cut_pos);
    buf->start_byte += cut_pos;
    buf->byte_cnt -= cut_pos;
    return 0;
}

static int dedupfs_release(const char *path, struct fuse_file_info *fi){
    // write back buffer data
    DEBUG_MESSAGE("[release]" << path);
    INUM_TYPE iNum = file_handler[fi->fh].iNum;
    int real_file_fh = file_handler[fi->fh].fh;
    buffer_entry *buf = &file_handler[fi->fh].write_buf;
    while(buf->byte_cnt > 0){
        int res = flush_buffer(buf, iNum, file_handler[fi->fh].csfh);
        if (res == -1) return -errno;
    }
    // pending chunk store
    char empty_buf[4096];
    int pending_size = SECTOR_SIZE - mapping_table[iNum].real_size % SECTOR_SIZE;
    pwrite(file_handler[fi->fh].csfh, empty_buf, pending_size, mapping_table[iNum].real_size);
    mapping_table[iNum].real_size += pending_size;
    // build real file mapping
    std::map<INUM_TYPE, int> fh_cache;  // I am not going to use fh in file handler because it might open as "write" mode
    INUM_TYPE pre_iNum = -1;
    off_t pre_last_sector = -1;
    for (GROUP_IDX_TYPE cur_group_idx = mapping_table[iNum].completed_link; cur_group_idx < mapping_table[iNum].group_pos.size(); cur_group_idx++){
        INUM_TYPE group_iNum = mapping_table[iNum].group_pos[cur_group_idx].iNum;
        if (fh_cache.find(group_iNum) == fh_cache.end()){
            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%s%s%s", BACKEND, CHUNK_STORE, iNum_to_path[group_iNum].c_str());
            fh_cache[group_iNum] = open(full_path, O_RDONLY);
        }
        size_t front_useless_size = mapping_table[iNum].group_pos[cur_group_idx].offset % SECTOR_SIZE;
        off_t src_offset = mapping_table[iNum].group_pos[cur_group_idx].offset - front_useless_size;
        size_t length = (mapping_table[iNum].group_pos[cur_group_idx].length + front_useless_size + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE;  // alligned with sector size
        bool use_same_sector = false;
        if (group_iNum == pre_iNum && src_offset / SECTOR_SIZE == pre_last_sector){
            length -= SECTOR_SIZE;
            src_offset += SECTOR_SIZE;
            use_same_sector = true;
        }
        struct file_clone_range range =  {
            fh_cache[group_iNum],
            (uint64_t)src_offset,  // src offset
            length, // src length
            mapping_table[iNum].virtual_size // dest offset
        };
        if (length > 0){
            int res = ioctl(real_file_fh, FICLONERANGE, &range);
            if (res == -1){
                perror("ioctl failed: ");
                PRINT_WARNING("src_offset->" << src_offset << " length->" << length << " chunk_file_size->" << mapping_table[iNum].real_size);
                return -errno;
            }
        }
        if (use_same_sector)
            mapping_table[iNum].group_virtual_offset.push_back(mapping_table[iNum].virtual_size + front_useless_size - SECTOR_SIZE);
        else
            mapping_table[iNum].group_virtual_offset.push_back(mapping_table[iNum].virtual_size + front_useless_size);
        mapping_table[iNum].virtual_size += length;
        mapping_table[iNum].completed_link++;
        pre_iNum = group_iNum;
        pre_last_sector = (src_offset + length - 1) / SECTOR_SIZE;
    }
    // release resource
    for (auto it = fh_cache.begin(); it != fh_cache.end(); it++)
        close(it->second);
    if (file_handler[fi->fh].mode == 'w'){
        close(file_handler[fi->fh].csfh);
        delete[] buf->content;
        buf->content = NULL;
    }
    close(real_file_fh);
    release_file_handler(fi->fh);
    return 0;
}

static int dedupfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
    DEBUG_MESSAGE("[write]" << path << " offset: " << offset << " size: " << size);
    std::unique_lock<std::shared_mutex> unique_write_record_lock(write_record_mutex);
    total_write_size += size;
    unique_write_record_lock.unlock();
    INUM_TYPE iNum = file_handler[fi->fh].iNum;
    buffer_entry *write_buf = &file_handler[fi->fh].write_buf;
    size_t less = size;
    char * buf_ptr = (char *)buf;
    if (write_buf->start_byte + write_buf->byte_cnt != offset) {
        PRINT_WARNING("write: detect not continous write in write buffer");
        return -EINVAL;
    }
    while (less > 0) {
        size_t fill_size = std::min((size_t)MAX_GROUP_SIZE - write_buf->byte_cnt, less);
        memcpy(write_buf->content+write_buf->byte_cnt, buf_ptr, fill_size);
        write_buf->byte_cnt += fill_size;
        less -= fill_size;
        buf_ptr += fill_size;
        if (write_buf->byte_cnt == MAX_GROUP_SIZE){
            int res = flush_buffer(write_buf, iNum, file_handler[fi->fh].csfh);
            if (res == -1) return -errno;
        }
    }
    mapping_table[iNum].logical_size += size;
    return size;
}