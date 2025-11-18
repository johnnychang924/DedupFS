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

#include "lru_list.h"
#include "def.h"

struct rewrite_req_struct{
    INUM_TYPE iNum;
    off_t logical_offset;
    char buffer[SECTOR_SIZE];
};

std::unordered_map<FP_TYPE, off_t> rewrite_fp_store;
off_t rewrite_file_size = 0;
LRU_list lru = LRU_list(LRU_LEN);

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
        new_mapping_table_entry.virtual_size = mapping_table[iNum].virtual_size;
        new_mapping_table_entry.real_size = mapping_table[iNum].real_size;
        GROUP_IDX_TYPE cur_group_idx;
        auto offset_it = pair.second.begin();
        // loop file's each group
        for (cur_group_idx = 0; cur_group_idx < mapping_table[iNum].group_pos.size(); cur_group_idx++){
            // check if this group needs to be rewritten
            off_t start_group_offset = mapping_table[iNum].group_logical_offset[cur_group_idx];
            off_t end_group_offset = start_group_offset + mapping_table[iNum].group_pos[cur_group_idx]->length;
            off_t cur_process_offset = start_group_offset;
            bool at_first = true;
            INUM_TYPE group_ori_iNum = mapping_table[iNum].group_pos[cur_group_idx]->iNum;
            while (cur_process_offset < end_group_offset){
                bool need_rewrite = offset_it != pair.second.end() && *offset_it <= end_group_offset;
                if (at_first && !need_rewrite){
                    // fast forward
                    new_mapping_table_entry.group_logical_offset.push_back(mapping_table[iNum].group_logical_offset[cur_group_idx]);
                    new_mapping_table_entry.group_pos.push_back(mapping_table[iNum].group_pos[cur_group_idx]);
                    cur_process_offset = end_group_offset;
                }
                else if(need_rewrite && cur_process_offset == *offset_it){
                    // rewrite page
                    off_t src_off;
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
                    if (offset_it != pair.second.end())
                        new_group_len = std::min(end_group_offset, *offset_it) - cur_process_offset;
                    else
                        new_group_len = end_group_offset - cur_process_offset;
                    chunk_addr *new_chunk_addr = new chunk_addr{ group_ori_iNum, new_group_pos_off, new_group_len };
                    new_mapping_table_entry.group_logical_offset.push_back(cur_process_offset);
                    new_mapping_table_entry.group_pos.push_back(new_chunk_addr);
                    cur_process_offset += new_group_len;
                }
                uint64_t end_logical_page = (mapping_table[iNum].group_logical_offset[cur_group_idx] + mapping_table[iNum].group_pos[cur_group_idx]->length) / CHUNK_SIZE;
                for(GROUP_IDX_TYPE i = new_mapping_table_entry.group_idx.size(); i <= end_logical_page; i++){
                    mapping_table[iNum].group_idx.push_back(new_mapping_table_entry.group_pos.size() - 1);
                }
                at_first = false;
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
    DEBUG_MESSAGE("[rewrite]");
    DEBUG_MESSAGE("Finding rewrite target");
    // find need to rewrite chunk
    std::map<INUM_TYPE, std::set<off_t>> rewrite_map;
    uint64_t have_rewrite_page = 0;
    while (have_rewrite_page < ONESHOT_REWRITE_COUNT && !lru.empty()){
        Node *head_node = lru.pop_head();
        DEBUG_MESSAGE("  iNum: " << head_node->iNum << " LPA: " << head_node->page_off);
        rewrite_map[head_node->iNum].insert(head_node->page_off);
        delete head_node;
        have_rewrite_page += 1;
    }
    // call rewrite_handler
    rewrite_handler(rewrite_map);
}