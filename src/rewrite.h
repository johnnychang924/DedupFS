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

#include "lfu_list.h"
#include "def.h"

struct rewrite_req_struct{
    INUM_TYPE iNum;
    off_t logical_offset;
    char buffer[SECTOR_SIZE];
};

std::unordered_map<FP_TYPE, off_t> rewrite_fp_store;
off_t rewrite_file_size = 0;
LFUList lfu;

uint64_t total_rewrite_size = 0;    // Total rewrite size(include duplicate page)
uint64_t real_rewrite_size = 0;     // real rewrite size to the disk(exclude deuplicate page)

extern mapping_table_entry mapping_table[MAX_INODE_NUM];
extern inline PATH_TYPE get_path(INUM_TYPE iNum);
extern inline int build_virtual_file(INUM_TYPE iNum, int fh);
extern inline INUM_TYPE get_inum(PATH_TYPE path_str);
extern inline int internal_read(INUM_TYPE iNum, int fh, char *buf, size_t size, off_t offset, size_t &io_size, size_t &real_io_size);

void rewrite_handler(std::map<INUM_TYPE, std::set<off_t>> rewrite_map){
    // rewrite file handler
    int rewrite_fh = open(BACKEND CHUNK_STORE REWRITE_FILE_PATH, O_RDWR | O_CREAT, 0666);
    if (rewrite_fh == -1){
        PRINT_WARNING("Can not open rewrite file");
        return;
    }
    INUM_TYPE rewrite_file_iNum = get_inum(REWRITE_FILE_PATH);
    // loop each file
    for (const auto& pair : rewrite_map) {
        // rename old virtual file & create new virtual file
        INUM_TYPE iNum = pair.first;
        std::string file_name = get_path(iNum);
        if (file_name == ""){
            PRINT_WARNING("can not find file path, iNum: " << iNum);
            return;
        }
        std::string old_file_name = file_name + "old";
        std::string full_file_path = BACKEND CHUNK_STORE + file_name;
        struct stat file_st;
        if (stat(full_file_path.c_str(), &file_st) != 0) {
            PRINT_WARNING("REWRITE failed: can not find file stat, path: " << full_file_path << " ,iNum: " << iNum);
            return;
        }
        rename((BACKEND + file_name).c_str(), (BACKEND + old_file_name).c_str());
        int file_fh = creat((BACKEND + file_name).c_str(), file_st.st_mode & 07777);
        int old_file_fh = open((BACKEND + old_file_name).c_str(), O_RDONLY);
        mapping_table_entry new_mapping_table_entry;
        new_mapping_table_entry.logical_size = mapping_table[iNum].logical_size;
        new_mapping_table_entry.real_size = mapping_table[iNum].real_size;
        GROUP_IDX_TYPE cur_group_idx;
        auto offset_it = pair.second.begin();
        off_t prev_cur_process_offset = -1;  // for debug use
        off_t cur_process_offset = 0;
        // loop file's each group
        for (cur_group_idx = 0; cur_group_idx < mapping_table[iNum].group_pos.size(); cur_group_idx++){
            // check if this group needs to be rewritten
            off_t start_group_offset = mapping_table[iNum].group_logical_offset[cur_group_idx];
            off_t end_group_offset = start_group_offset + mapping_table[iNum].group_pos[cur_group_idx]->length;
            INUM_TYPE group_ori_iNum = mapping_table[iNum].group_pos[cur_group_idx]->iNum;
            while (cur_process_offset < end_group_offset){
                //PRINT_MESSAGE("start_group_offset: " << start_group_offset << " cur_process_offset: " << cur_process_offset << " end_group_offset: " << end_group_offset);
                bool need_rewrite = offset_it != pair.second.end() && *offset_it < end_group_offset;
                need_rewrite = need_rewrite && *offset_it + SECTOR_SIZE <= (off_t)mapping_table[iNum].logical_size;
                bool at_first = cur_process_offset == start_group_offset;
                if (cur_process_offset <= prev_cur_process_offset) [[unlikely]] {
                    PRINT_WARNING("rewrite error: cur_process_offset not moving forward");
                    PRINT_WARNING("group_idx: " << cur_group_idx);
                    PRINT_WARNING("start_group_offset: " << start_group_offset);
                    PRINT_WARNING("prev_cur_process_offset: " << prev_cur_process_offset);
                    PRINT_WARNING("cur_process_offset: " << cur_process_offset);
                    PRINT_WARNING("end_group_offset: " << end_group_offset);
                    PRINT_WARNING("next offset to rewrite: " << (offset_it != pair.second.end() ? *offset_it : -1));
                    PRINT_WARNING("logical_size: " << mapping_table[iNum].logical_size);
                    PRINT_WARNING("need_rewrite: " << need_rewrite);
                    PRINT_WARNING("at_first: " << at_first);
                    return;
                }
                prev_cur_process_offset = cur_process_offset;
                if (at_first && !need_rewrite){
                    // fast forward
                    new_mapping_table_entry.group_logical_offset.push_back(start_group_offset);
                    new_mapping_table_entry.group_pos.push_back(mapping_table[iNum].group_pos[cur_group_idx]);
                    cur_process_offset = end_group_offset;
                }
                else if(need_rewrite && cur_process_offset == *offset_it){
                    // rewrite page
                    off_t src_off;
                    total_rewrite_size += SECTOR_SIZE;
                    #ifdef REWRITE_DEDUP
                    // write out need to rewrite page
                    char buf[SECTOR_SIZE];
                    size_t io_size, real_io_size;   // just for internal_read
                    internal_read(iNum, old_file_fh, buf, SECTOR_SIZE, cur_process_offset, io_size, real_io_size);
                    // calculate new FP
                    char tmp_fp[SHA_DIGEST_LENGTH];
                    SHA1((const unsigned char *)buf, SECTOR_SIZE, (unsigned char *)tmp_fp);
                    FP_TYPE fp(tmp_fp, SHA_DIGEST_LENGTH);
                    // check FP exist in rewrite file
                    auto fp_store_iter = rewrite_fp_store.find(fp);
                    if (fp_store_iter == rewrite_fp_store.end()){
                        real_rewrite_size += SECTOR_SIZE;
                        pwrite(rewrite_fh, buf, SECTOR_SIZE, rewrite_file_size);
                        rewrite_fp_store[fp] = rewrite_file_size;
                        src_off = rewrite_file_size;
                        rewrite_file_size += SECTOR_SIZE;
                    }
                    else src_off = fp_store_iter->second;
                    #else
                    char buf[SECTOR_SIZE];
                    size_t io_size, real_io_size;   // just for internal_read
                    internal_read(iNum, old_file_fh, buf, SECTOR_SIZE, cur_process_offset, io_size, real_io_size);
                    real_rewrite_size += SECTOR_SIZE;
                    pwrite(rewrite_fh, buf, SECTOR_SIZE, rewrite_file_size);
                    src_off = rewrite_file_size;
                    rewrite_file_size += SECTOR_SIZE;
                    #endif
                    chunk_addr *new_chunk_addr = new chunk_addr{ rewrite_file_iNum, src_off, SECTOR_SIZE };
                    new_mapping_table_entry.group_logical_offset.push_back(cur_process_offset);
                    new_mapping_table_entry.group_pos.push_back(new_chunk_addr);
                    cur_process_offset += SECTOR_SIZE;
                    offset_it++;
                }
                else{
                    // create partial group
                    uint16_t front_gap = cur_process_offset - start_group_offset;
                    off_t new_group_pos_off = mapping_table[iNum].group_pos[cur_group_idx]->offset + front_gap;
                    size_t new_group_len;
                    if (need_rewrite)
                        new_group_len = *offset_it - cur_process_offset;
                    else
                        new_group_len = end_group_offset - cur_process_offset;
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
        // update mapping table
        mapping_table[iNum] = new_mapping_table_entry;
        // rebuild ioctl
        build_virtual_file(iNum, file_fh);
        close(file_fh);
        close(old_file_fh);
        remove((BACKEND + old_file_name).c_str());
    }
    close(rewrite_fh);
}

// rewrite wrapper
void rewrite(){
    #ifdef REWRITE
    DEBUG_MESSAGE("[rewrite]");
    DEBUG_MESSAGE("Finding rewrite target");
    // find need to rewrite chunk
    std::map<INUM_TYPE, std::set<off_t>> rewrite_map;
    uint64_t have_rewrite_page = 0;
    std::vector<uint64_t> rewrite_target = lfu.topK(ONESHOT_REWRITE_COUNT);
    for (auto lpa : rewrite_target) {
        INUM_TYPE iNum = lpa >> 32;
        off_t page_off = (lpa & 0xFFFFFFFF) * SECTOR_SIZE;
        DEBUG_MESSAGE("  iNum: " << iNum << " LPA: " << page_off);
        rewrite_map[iNum].insert(page_off);
        have_rewrite_page += 1;
    }
    // call rewrite_handler
    rewrite_handler(rewrite_map);
    #else
    PRINT_WARNING("rewrite is not enabled !!");
    #endif
}