#include <fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <unordered_map>
#include <map>
#include <openssl/sha.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cmath>
#include <mutex>
#include <shared_mutex>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <time.h>

#include "freq_tracker.h"
#include "metadata.h"
#include "rewrite.h"
#include "def.h"

/*
**  frequency tracker
*/
#if defined(INLINE_REWRITE)
FreqTracker freq_tracker;
#endif


static int dedupfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    DEBUG_MESSAGE("[create]" << path);
    if (strncmp(path, REWRITE_FILE_PATH, sizeof(REWRITE_FILE_PATH)) == 0)
        // conflict with system file, refuse to create file
        return -1;
    int real_file_handler, chunk_store_file_handler;
    char full_path[1024];
    char chunk_store_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    snprintf(chunk_store_path, sizeof(chunk_store_path), "%s%s%s", BACKEND, CHUNK_STORE, path);
    real_file_handler = creat(full_path, mode);
    if (real_file_handler == -1) return -errno;
    chunk_store_file_handler = creat(chunk_store_path, mode);
    if (chunk_store_file_handler == -1) return -errno;
    fi->fh = get_file_handler();
    if (fi->fh == (FILE_HANDLER_INDEX_TYPE)-1) return -errno;
    init_file_handler(path, fi->fh, real_file_handler, chunk_store_file_handler, 'w');
    // init global read fh for this inode (same inode survives build_virtual_file)
    INUM_TYPE iNum = file_handler[fi->fh].iNum;
    int old_read_fh = virtual_file_read_fh[iNum];
    virtual_file_read_fh[iNum] = open(full_path, O_RDONLY | O_DIRECT);
    int result = posix_fadvise(virtual_file_read_fh[iNum], 0, 0, POSIX_FADV_RANDOM);
    if (result != 0) PRINT_WARNING("Can not set POSIX_FADV_RANDOM");
    if (old_read_fh > 0) close(old_read_fh);
    fi->direct_io = 1;
    return 0;
}

static int dedupfs_open(const char *path, struct fuse_file_info *fi) {
    DEBUG_MESSAGE("[open]" << path);
    int real_file_handler, chunk_store_file_handler;
    char full_path[1024];
    char chunk_store_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", BACKEND, path);
    snprintf(chunk_store_path, sizeof(chunk_store_path), "%s%s%s", BACKEND, CHUNK_STORE, path);
    real_file_handler = open(full_path, fi->flags | O_DIRECT);
    if (real_file_handler == -1) return -errno;
    if (fi->flags & (O_WRONLY | O_RDWR)) {      // need to write
        chunk_store_file_handler = open(chunk_store_path, fi->flags | O_DIRECT);
        if (chunk_store_file_handler == -1) return -errno;
    }
    else chunk_store_file_handler = -1;
    fi->fh = get_file_handler();
    if (fi->fh == -1ULL) return -errno;
    char mode = fi->flags & (O_WRONLY | O_RDWR) ? 'w' : 'r';
    DEBUG_MESSAGE("mode: " << mode);
    init_file_handler(path, fi->fh, real_file_handler, chunk_store_file_handler, mode);
    fi->direct_io = 1;
    return 0;
}
// for dedupfs internal read
inline int internal_read(INUM_TYPE iNum, int fh, char *buf, size_t size, off_t offset, size_t &io_size, size_t &real_io_size){
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
        if (start_group_idx < 0 || start_group_idx >= mapping_table[iNum].group_pos.size()) return 0;   // It should not happen
    }
    DEBUG_MESSAGE("  start block: " << start_group_idx);
    // find need to read range
    off_t end_off = offset + size;
    off_t front_gap = offset - mapping_table[iNum].group_logical_offset[start_group_idx];
    if (start_group_idx > mapping_table[iNum].completed_link){
        PRINT_WARNING("[warning] trying to read unreferenced group, group_idx: " << start_group_idx);
        return 0;
    }
    // off_t io_off = (mapping_table[iNum].group_virtual_offset[start_group_idx] + front_gap) / SECTOR_SIZE * SECTOR_SIZE;
    // just for validate
    // real_io_size = mapping_table[iNum].group_virtual_offset[start_group_idx] + front_gap;
    GROUP_IDX_TYPE cur_group_idx = start_group_idx;
    while(cur_group_idx < mapping_table[iNum].group_logical_offset.size() && 
                mapping_table[iNum].group_logical_offset[cur_group_idx] < end_off)
        cur_group_idx++;
    cur_group_idx -= 1;
    if (cur_group_idx > mapping_table[iNum].completed_link){
        PRINT_WARNING("[warning] trying to read unreferenced group, group_idx: " << start_group_idx);
        return 0;
    }

    off_t end_gap = mapping_table[iNum].group_logical_offset[cur_group_idx] + mapping_table[iNum].group_pos[cur_group_idx]->length - end_off;
    if (end_gap < 0) end_gap = 0;   // end_off might bigger than logical file size
    // find smallest need to read area
    off_t io_start = OFF_T_MAX, io_end = 0;
    for (GROUP_IDX_TYPE i = start_group_idx; i <= cur_group_idx; i++){
        off_t group_start = mapping_table[iNum].group_virtual_offset[i];
        off_t group_end = group_start + mapping_table[iNum].group_pos[cur_group_idx]->length;
        if (i == start_group_idx) group_start += front_gap;
        if (i == cur_group_idx) group_end -= end_gap;
        io_start = std::min(io_start, group_start);
        io_end = std::max(io_end, group_end);
    }
    real_io_size = io_end - io_start;
    if (io_end < io_start) [[unlikely]] PRINT_WARNING("io_end < io_start" << io_end << ", " << io_start);
    off_t io_off = io_start / SECTOR_SIZE * SECTOR_SIZE;
    io_size = (io_end + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE - io_off;

    //io_size = mapping_table[iNum].group_virtual_offset[cur_group_idx] + (off_t)mapping_table[iNum].group_pos[cur_group_idx]->length - end_gap - io_off;
    //io_size = (io_size + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE;  // allign with page

    // just for validate
    // real_io_size = mapping_table[iNum].group_virtual_offset[cur_group_idx] + (off_t)mapping_table[iNum].group_pos[cur_group_idx]->length - end_gap - real_io_size;
    // PRINT_WARNING("real_io_size: " << real_io_size << " io_start: " << io_start << " io_end: " << io_end);
    
    // read into temp buffer
    // char tmp_buf[io_size];
    char *tmp_buf;
    if (posix_memalign((void**)&tmp_buf, 4096, io_size) != 0){
        PRINT_WARNING("posix_memalign failed!!!!");
        return -1;
    }
    //auto tmp_buf_chunk = std::unique_ptr<char, decltype(&free)>(
    //    (char *)aligned_alloc(SECTOR_SIZE, io_size), free);
    //if (!tmp_buf_chunk) return -ENOMEM;
    //char *tmp_buf = tmp_buf_chunk.get();
    DEBUG_MESSAGE("  start reading offset->" << io_off << " size->" << io_size);
    int res = pread(virtual_file_read_fh[iNum], tmp_buf, io_size, io_off);
    if ((size_t)res != io_size){
        PRINT_WARNING("Can not read enough chunk from virtual file, should read " << io_size << ", but " << res);
    }
    // fill in return buffer
    int less = size;
    char *cur_buf_ptr = buf;
    cur_group_idx = start_group_idx;
    front_gap = offset - mapping_table[iNum].group_logical_offset[start_group_idx];
    DEBUG_MESSAGE("  filling return buffer");
    while(less > 0){
        size_t cp_size = std::min(mapping_table[iNum].group_pos[cur_group_idx]->length - (size_t)front_gap, (size_t)less);
        off_t tmp_buf_off = mapping_table[iNum].group_virtual_offset[cur_group_idx] - io_off + front_gap;
        // if (tmp_buf_off < 0 || tmp_buf_off + cp_size > io_size) PRINT_WARNING("read outside of buffer " << io_size << ", " << tmp_buf_off << ", " << cp_size);
        DEBUG_MESSAGE("    cur_group->" << cur_group_idx << " front_gap->" << front_gap << " cp_size->" << cp_size << " group_offset->" << mapping_table[iNum].group_virtual_offset[cur_group_idx] << " group_size->" << mapping_table[iNum].group_pos[cur_group_idx]->length << " tmp_buffer_offset->" << tmp_buf_off);
        memcpy(cur_buf_ptr, tmp_buf + tmp_buf_off, cp_size);
        less -= cp_size;
        if (cur_group_idx == mapping_table[iNum].group_pos.size()-1) break;
        cur_buf_ptr += cp_size;
        cur_group_idx++;
        front_gap = 0;
    }
    free(tmp_buf);
    return size - std::max(less, 0);
}

static int dedupfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
    DEBUG_MESSAGE("[read]" << path << " offset: " << offset << " size: " << size);
    
    INUM_TYPE iNum = file_handler[fi->fh].iNum;
    if ((size_t)offset > mapping_table[iNum].logical_size || size == 0) return 0;
    size_t real_io_size = 0;
    size_t io_size = 0;
    int ret;
    #if defined(INLINE_REWRITE)
    int local_remap_pread_count = 0;
    {
        off_t end = std::min(offset + (off_t)size, (off_t)mapping_table[iNum].logical_size);
        // snapshot in-range remap entries, then release the lock immediately
        std::vector<std::pair<off_t, off_t>> snapshot;
        snapshot.reserve(((end - offset / SECTOR_SIZE * SECTOR_SIZE) + SECTOR_SIZE - 1) / SECTOR_SIZE);
        {
            std::shared_lock<std::shared_mutex> remap_lock(mapping_table_remap_mutex[iNum]);
            auto& remap = mapping_table[iNum].remap;
            for (off_t pg = (offset / SECTOR_SIZE) * SECTOR_SIZE; pg < end; pg += SECTOR_SIZE) {
                auto it = remap.find(pg);
                if (it != remap.end()) snapshot.emplace_back(pg, it->second);
            }
        }
        int total_read = 0;
        size_t snap_idx = 0;
        off_t cur = offset;
        while (cur < end) {
            off_t page_off = cur / SECTOR_SIZE * SECTOR_SIZE;
            if (snap_idx < snapshot.size() && snapshot[snap_idx].first == page_off) {
                // remapped run: extend while contiguous in both logical and physical space
                off_t run_logical_start = page_off;
                off_t run_src_start = snapshot[snap_idx].second;
                size_t run_pages = 1;
                while (snap_idx + run_pages < snapshot.size() &&
                       snapshot[snap_idx + run_pages].first == run_logical_start + (off_t)(run_pages * SECTOR_SIZE) &&
                       snapshot[snap_idx + run_pages].second == run_src_start + (off_t)(run_pages * SECTOR_SIZE)) {
                    ++run_pages;
                }
                off_t run_logical_end = run_logical_start + (off_t)(run_pages * SECTOR_SIZE);
                off_t in_run_offset = cur - run_logical_start;
                size_t copy_size = std::min(run_logical_end, end) - cur;
                char *tmp_buf;
                if (posix_memalign((void**)&tmp_buf, 4096, copy_size) != 0){
                    PRINT_WARNING("posix_memalign failed!!!!");
                    return -1;
                }
                int res = pread(rewrite_read_fh, tmp_buf, copy_size, run_src_start + in_run_offset);
                if (copy_size % 4096 != 0 || (run_src_start + in_run_offset) % 4096 != 0) [[unlikely]] PRINT_WARNING("Can not use direct I/O");
                memcpy(buf + (cur - offset), tmp_buf, copy_size);
                free(tmp_buf);
                local_remap_pread_count += 1;
                if ((size_t)res != copy_size) [[unlikely]] {
                    PRINT_WARNING("remap pread failed: read " << res << " expected " << copy_size);
                    return 0;
                }
                io_size += copy_size;
                real_io_size += copy_size;
                total_read += copy_size;
                cur += copy_size;
                snap_idx += run_pages;
            } else {
                // non-remapped run: defer to internal_read up to next remapped page (or end)
                off_t next_remap = (snap_idx < snapshot.size()) ? snapshot[snap_idx].first : end;
                off_t run_end = std::min(next_remap, end);
                size_t sub_io = 0, sub_real_io = 0;
                int sub_ret = internal_read(iNum, virtual_file_read_fh[iNum],
                                            buf + (cur - offset),
                                            run_end - cur, cur, sub_io, sub_real_io);
                if (sub_ret == 0) return 0;
                io_size += sub_io;
                real_io_size += sub_real_io;
                total_read += sub_ret;
                cur = run_end;
            }
            if (cur < end)[[unlikely]] PRINT_WARNING("Read didn't complete after one round");
        }
        ret = total_read;
    }
    #else
    ret = internal_read(iNum, virtual_file_read_fh[iNum], buf, size, offset, io_size, real_io_size);
    #endif
    if (ret == 0)
        return ret;     // something went wrong, return the process to prevent more system damage
    
    #if defined(INLINE_REWRITE)
    if (io_size != size && running) {
        float min_score = std::numeric_limits<float>::max();
        for (off_t LPA = offset / SECTOR_SIZE; LPA < (offset + (off_t)size + SECTOR_SIZE - 1) / SECTOR_SIZE; LPA++)
            min_score = std::min(min_score, freq_tracker.read(iNum, LPA));
        float extra_read_pages = (float)(io_size - size) / SECTOR_SIZE;
        if (min_score * extra_read_pages > INLINE_REWRITE_THRESHOLD) {
            // phase 1: build rewrite requests under mapping table shared lock only
            std::vector<rewrite_req_struct> pending;
            {
                std::shared_lock<std::shared_mutex> read_lock(mapping_table_mutex[iNum]);
                for (off_t LPA = offset / SECTOR_SIZE; LPA < (offset + (off_t)size + SECTOR_SIZE - 1) / SECTOR_SIZE; LPA++) {
                    if (mapping_table[iNum].has_rewrite.size() <= (uint64_t)LPA || mapping_table[iNum].has_rewrite[LPA]) continue;
                    off_t page_offset = LPA * SECTOR_SIZE;
                    off_t buf_off = page_offset - offset;
                    if (buf_off < 0 || buf_off + SECTOR_SIZE > offset + (off_t)size) continue;
                    // skip pages that are already sector-aligned in the virtual file
                    // (reading them causes no amplification, so rewriting them is unnecessary)
                    /*GROUP_IDX_TYPE gidx = mapping_table[iNum].group_idx[LPA];
                    off_t front_gap = page_offset - mapping_table[iNum].group_logical_offset[gidx];
                    off_t virt_start = mapping_table[iNum].group_virtual_offset[gidx] + front_gap;
                    if ((size_t)front_gap + SECTOR_SIZE <= mapping_table[iNum].group_pos[gidx]->length
                        && virt_start % SECTOR_SIZE == 0) continue;*/
                    rewrite_req_struct req;
                    req.iNum = iNum;
                    req.logical_offset = page_offset;
                    memcpy(req.buffer, buf + buf_off, SECTOR_SIZE);
                    pending.push_back(std::move(req));
                }
            }
            // phase 2: push to queue under exclusive lock (brief critical section)
            if (!pending.empty()) {
                {
                    std::unique_lock<std::shared_mutex> queue_lock(rewrite_queue_mutex);
                    if (rewrite_queue.size() < INLINE_REWRITE_QUEUE_MAX){
                        for (auto& req : pending) {
                            mapping_table[req.iNum].has_rewrite[req.logical_offset / SECTOR_SIZE] = true;
                            rewrite_queue.push_back(std::move(req));
                        }
                    }
                }
                #ifdef INLINE_REWRITE
                inline_rewrite_cv.notify_one();
                #endif
            }
        }
    }
    #endif
    if (real_io_size > io_size) [[unlikely]] PRINT_WARNING("ERROR: io_size > real_io_size" << io_size << ", " << real_io_size);

    // record fs read information
    std::unique_lock<std::shared_mutex> unique_read_record_lock(read_record_mutex);
    host_read_size += std::abs((off_t)std::min(offset + size, mapping_table[iNum].logical_size) - offset);
    fuse_read_size += io_size;
    if (io_size <= size && real_io_size <= size) read_req_align += 1;
    else if (io_size > size && real_io_size <= size) read_req_misalign += 1;
    else read_req_frag += 1;
    #if defined(INLINE_REWRITE)
    remap_pread_count += local_remap_pread_count;
    if (local_remap_pread_count != 0) remap_req_count += 1;
    #endif
    unique_read_record_lock.unlock();

    return ret;
}

inline int pending_disk(int fh, INUM_TYPE iNum, off_t target_offset){
    DEBUG_MESSAGE("  pending disk for file handler: " << fh << " target_offset: " << target_offset);
    int pending_size = (target_offset % SECTOR_SIZE) - (mapping_table[iNum].real_size % SECTOR_SIZE);
    if (pending_size < 0)
        pending_size += SECTOR_SIZE;
    if (pending_size != 0){
        mapping_table[iNum].real_size += pending_size;
        ftruncate(fh, mapping_table[iNum].real_size);
    }
    return pending_size;
}

/*
* write back content(in buffer or in chunk store) into disk
*/
inline int writeback_disk(INUM_TYPE iNum, GROUP_IDX_TYPE group_idx, int fh, char *buf, size_t size){
    DEBUG_MESSAGE("  write back disk for iNum: " << iNum << " group_idx: " << group_idx << " size: " << size);
    if (size == 0) return 0;
    if (group_idx >= mapping_table[iNum].group_pos.size()){
        PRINT_WARNING("  group_idx is out of range, group_idx: " << group_idx << " size: " << mapping_table[iNum].group_pos.size());
        return -1;
    }
    // pending disk
    #ifdef PENDING
    int pending_size = pending_disk(fh, iNum, mapping_table[iNum].group_logical_offset[group_idx]);
    std::unique_lock<std::shared_mutex> unique_write_record_lock(write_record_mutex);
    total_padding_size += pending_size;
    unique_write_record_lock.unlock();
    #endif
    DEBUG_MESSAGE("Pending success");
    int res = pwrite(fh, buf, size, mapping_table[iNum].real_size);
    if (res != (int)size){
        PRINT_WARNING("  write back disk failed, expected " << size << " but got " << res);
        return res;
    }
    // update mapping table
    DEBUG_MESSAGE("  update mapping table for iNum: " << iNum << " group_idx: " << group_idx << " (" << mapping_table[iNum].group_pos.size() << " groups)");
    mapping_table[iNum].group_pos[group_idx]->length = size;
    mapping_table[iNum].group_pos[group_idx]->offset = mapping_table[iNum].real_size;
    mapping_table[iNum].real_size += size;
    return res;
}

#ifdef CHUNK_CACHE_SIZE
/*
* writeback one entry in chunk store into disk
*/
inline int flush_chunkstore(FILE_HANDLER_INDEX_TYPE fh_index){
    DEBUG_MESSAGE("  flush chunk store for file handler: " << fh_index);
    chunkstore_entry *chunkstore = file_handler[fh_index].chunkstore;
    INUM_TYPE iNum = file_handler[fh_index].iNum;
    off_t disk_offset = mapping_table[iNum].real_size % SECTOR_SIZE;  // current disk offset in sector size
    uint32_t chunk_count = file_handler[fh_index].chunk_count;
    if (chunk_count == 0){
        PRINT_WARNING("  chunk store is empty, nothing to flush");
        return 0;
    }
    // find best write chunk
    uint16_t victim_chunk_idx = -1;
    uint16_t victim_chunk_offset = SECTOR_SIZE+1;
    // try best fit first
    for (uint32_t i = 0; i < chunk_count; i++){
        uint16_t cur_offset = chunkstore[i].logical_offset % SECTOR_SIZE;
        if (cur_offset >= disk_offset && cur_offset < victim_chunk_offset){
            victim_chunk_idx = i;
            victim_chunk_offset = cur_offset;
        }
    }
    // if best fit not found, use smallest chunk offset
    if (victim_chunk_idx == uint16_t(-1)){
        DEBUG_MESSAGE("  best fit chunk not found, using smallest chunk offset");
        for (uint32_t i = 0; i < chunk_count; i++){
            uint16_t cur_offset = chunkstore[i].logical_offset % SECTOR_SIZE;
            if (cur_offset < victim_chunk_offset){
                victim_chunk_idx = i;
                victim_chunk_offset = cur_offset;
            }
        }
    }
    // start write back chunk
    DEBUG_MESSAGE("  victim chunk index: " << victim_chunk_idx << " offset: " << chunkstore[victim_chunk_idx].logical_offset << " size: " << chunkstore[victim_chunk_idx].length);
    int res = writeback_disk(iNum, chunkstore[victim_chunk_idx].group_idx, file_handler[fh_index].csfh, chunkstore[victim_chunk_idx].content, chunkstore[victim_chunk_idx].length);
    // remove this chunk from chunk store
    char *victim_chunk_content = chunkstore[victim_chunk_idx].content;
    for (uint32_t i = victim_chunk_idx + 1; i < chunk_count; i++){
        chunkstore[i-1] = chunkstore[i];
    }
    chunkstore[chunk_count-1].content = victim_chunk_content;
    file_handler[fh_index].chunk_count--;
    return res;
}

inline int insert_chunkstore(FILE_HANDLER_INDEX_TYPE fh_index, const char *buf, size_t size, off_t offset, GROUP_IDX_TYPE group_idx){
    DEBUG_MESSAGE("  insert chunk store for file handler: " << fh_index << " offset: " << offset << " size: " << size << " group_idx: " << group_idx);
    chunkstore_entry *chunkstore = file_handler[fh_index].chunkstore;
    if (file_handler[fh_index].chunk_count >= CHUNK_CACHE_SIZE){
        DEBUG_MESSAGE("  chunk store is full");
        int res = flush_chunkstore(fh_index);
        if (res == -1) return -1;
    }
    int chunk_index = file_handler[fh_index].chunk_count++;
    memcpy(chunkstore[chunk_index].content, buf, size);
    chunkstore[chunk_index].group_idx = group_idx;
    chunkstore[chunk_index].logical_offset = offset;
    chunkstore[chunk_index].length = size;
    DEBUG_MESSAGE("  chunk store count(after insert): " << chunk_index + 1);
    return size;
}
#endif

inline int flush_buffer(buffer_entry *buf, INUM_TYPE iNum, int csfh, FILE_HANDLER_INDEX_TYPE fh_index){       // return actual size write into disk
    DEBUG_MESSAGE("  flush buffer: " << iNum << " buf size: " << buf->byte_cnt);
    // chunking
    std::unique_lock<std::shared_mutex> unique_chunker_lock(chunker_mutex);
    int cut_pos = cut((const uint8_t*)buf->content, MAX_GROUP_SIZE, cdc_setting.mi, cdc_setting.ma, cdc_setting.ns,
                      cdc_setting.mask_s, cdc_setting.mask_l);
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
    // scan duplicate target
    int found_target_index = -1;
    #ifdef allign_dedup
    if (fp_store_iter != fp_store.end()){
        for (int index = 0; index < (int)fp_store[fp].address_list.size(); index++){
            if (fp_store[fp].address_list[index]->offset % CHUNK_SIZE == buf->start_byte % CHUNK_SIZE)
                found_target_index = index;
        }
    }
    else{
        fp_store[fp] = {0, std::vector<chunk_addr*>()};
    }
    #else
    if (fp_store_iter != fp_store.end()){
        found_target_index = 0;
    }
    #endif
    mapping_table[iNum].group_logical_offset.push_back(buf->start_byte);
    if (found_target_index != -1){   // found
        DEBUG_MESSAGE("    found duplicate group!!");
        fp_store_iter->second.ref_times += 1;
        mapping_table[iNum].group_pos.push_back(fp_store_iter->second.address_list[found_target_index]);
    }
    else{   // not found
        chunk_addr *new_chunk_addr = new chunk_addr{ iNum, 0, 0 };
        mapping_table[iNum].group_pos.push_back(new_chunk_addr);
        #ifdef CHUNK_CACHE_SIZE
        int res = insert_chunkstore(fh_index, buf->content, cut_pos, buf->start_byte, mapping_table[iNum].group_pos.size() - 1);
        #else
        int res = writeback_disk(iNum, mapping_table[iNum].group_pos.size()-1, csfh, buf->content, cut_pos);
        #endif
        if (res != cut_pos) return -1;
        std::unique_lock<std::shared_mutex> unique_fp_store_lock(fp_store_mutex);
        #ifndef NODEDUPE
        // fp_store[fp] = {1, new_chunk_addr};
        fp_store[fp].ref_times += 1;
        fp_store[fp].address_list.push_back(new_chunk_addr);
        #endif
        real_write_size += cut_pos;    // borrow fp store's lock
        unique_fp_store_lock.unlock();
    }
    for(GROUP_IDX_TYPE i = mapping_table[iNum].group_idx.size(); i <= (buf->start_byte + cut_pos - 1) / CHUNK_SIZE; i++){
        mapping_table[iNum].group_idx.push_back(mapping_table[iNum].group_pos.size() - 1);
        mapping_table[iNum].has_rewrite.push_back(false);
        #ifdef RECORD_LATENCY
        each_file_read_bandwidth[iNum].lat.push_back(0);
        each_file_read_bandwidth[iNum].count.push_back(0);
        #endif
    }
    if (buf->byte_cnt - cut_pos > 0)
        memcpy(buf->content, buf->content+cut_pos, buf->byte_cnt - cut_pos);
    buf->start_byte += cut_pos;
    buf->byte_cnt -= cut_pos;
    return 0;
}

inline int build_virtual_file(mapping_table_entry& entry, int fh){
    std::map<INUM_TYPE, int> fh_cache;  // I am not going to use fh in file handler because it might open as "write" mode
    INUM_TYPE pre_iNum = -1;
    off_t pre_last_sector = -1;
    for (GROUP_IDX_TYPE cur_group_idx = entry.completed_link; cur_group_idx < entry.group_pos.size(); cur_group_idx++){
        INUM_TYPE group_iNum = entry.group_pos[cur_group_idx]->iNum;
        if (fh_cache.find(group_iNum) == fh_cache.end()){
            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%s%s%s", BACKEND, CHUNK_STORE, iNum_to_path[group_iNum].c_str());
            DEBUG_MESSAGE("open path: " << full_path);
            fh_cache[group_iNum] = open(full_path, O_RDONLY);
            if (fh_cache[group_iNum] == -1){
                PRINT_WARNING("can not open path: " << full_path);
                return -1;
            }
        }
        size_t front_useless_size = entry.group_pos[cur_group_idx]->offset % SECTOR_SIZE;
        off_t src_offset = entry.group_pos[cur_group_idx]->offset - front_useless_size;
        size_t length = (entry.group_pos[cur_group_idx]->length + front_useless_size + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE;  // alligned with sector size
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
            entry.virtual_size // dest offset
        };
        if (length > 0){
            int res = ioctl(fh, FICLONERANGE, &range);
            if (res == -1){
                perror("ioctl failed: ");
                PRINT_WARNING("src_offset->" << src_offset << " length->" << length << " chunk_file_size->" << entry.real_size);
                return -errno;
            }
        }
        if (use_same_sector)
            entry.group_virtual_offset.push_back(entry.virtual_size + front_useless_size - SECTOR_SIZE);
        else
            entry.group_virtual_offset.push_back(entry.virtual_size + front_useless_size);
        entry.virtual_size += length;
        entry.completed_link++;
        pre_iNum = group_iNum;
        pre_last_sector = (src_offset + length - 1) / SECTOR_SIZE;
    }
    // release resource
    for (auto it = fh_cache.begin(); it != fh_cache.end(); it++)
        close(it->second);
    return 0;
}

inline int build_virtual_file(INUM_TYPE iNum, int fh){
    return build_virtual_file(mapping_table[iNum], fh);
}

static int dedupfs_flush(const char *path, struct fuse_file_info *fi){
    // write back buffer data
    DEBUG_MESSAGE("[flush]" << path);
    INUM_TYPE iNum = file_handler[fi->fh].iNum;
    int real_file_fh = file_handler[fi->fh].fh;
    buffer_entry *buf = &file_handler[fi->fh].write_buf;
    while(buf->byte_cnt > 0){
        int res = flush_buffer(buf, iNum, file_handler[fi->fh].csfh, fi->fh);
        if (res == -1) return -errno;
    }
    // write back chunk store
    #ifdef CHUNK_CACHE_SIZE
    while(file_handler[fi->fh].chunk_count){
        int res = flush_chunkstore(fi->fh);
        if (res == -1) return -errno;
    }
    file_handler[fi->fh].chunk_count = 0;
    #endif
    // pending chunk store
    char empty_buf[SECTOR_SIZE];
    int pending_size = SECTOR_SIZE - mapping_table[iNum].real_size % SECTOR_SIZE;
    if (pending_size != SECTOR_SIZE){
        pwrite(file_handler[fi->fh].csfh, empty_buf, pending_size, mapping_table[iNum].real_size);
        mapping_table[iNum].real_size += pending_size;
    }
    // build real file mapping
    build_virtual_file(iNum, real_file_fh);
    return 0;
}

static int dedupfs_release(const char *path, struct fuse_file_info *fi){
    DEBUG_MESSAGE("[release]" << path);
    int real_file_fh = file_handler[fi->fh].fh;
    buffer_entry *buf = &file_handler[fi->fh].write_buf;
    // release resource
    if (file_handler[fi->fh].mode == 'w'){
        close(file_handler[fi->fh].csfh);
        delete[] buf->content;
        buf->content = NULL;
        #ifdef CHUNK_CACHE_SIZE
        for (int i = 0; i < CHUNK_CACHE_SIZE; i++)
            delete[] file_handler[fi->fh].chunkstore[i].content;
        #endif
    }
    // DEBUG_MESSAGE("  real file size: " << mapping_table[iNum].real_size << " logical file size: " << mapping_table[iNum].logical_size);
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
            int res = flush_buffer(write_buf, iNum, file_handler[fi->fh].csfh, fi->fh);
            if (res == -1) return -errno;
        }
    }
    mapping_table[iNum].logical_size += size;
    return size;
}
