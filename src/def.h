#include <iostream>
#include <vector>
#include <cstdint>

#ifndef DEF_H
#define DEF_H

// DedupFS user setting
#define BACKEND "/home/johnnychang/Projects/CDC-dedup/helper/bak"
#define MAX_GROUP_SIZE 16384
#define BLOCK_SIZE 4096
#define SSD_ONESHOT 4096
#define SECTOR_SIZE 4096

// don't change it!
#define MAX_INODE_NUM 1048576
#define MAX_FILE_HANDLER 256

// type define
#define INUM_TYPE unsigned long
#define FP_TYPE std::string
#define PATH_TYPE std::string
#define FILE_HANDLER_INDEX_TYPE uint8_t

// struct define
struct range{
    off_t offset;
    size_t length;
};
struct hash_store_entry{
    INUM_TYPE inum;
    range address;
};
struct group_addr{
    INUM_TYPE iNum;
    uint32_t start_byte;    // start byte in that file
    uint16_t group_length;  // the length of this group
    uint8_t ref_times;      // how many times this group is referenced
};
struct mapping_table_entry{
    std::vector<int> group_idx;                 // the group index of each "BLOCK"
    std::vector<off_t> group_offset;    // the start byte of every group in this file
    std::vector<group_addr *> group_pos;        // The position of every Group
    std::vector<FP_TYPE> fp_list;               // fingerprint of every Group
    unsigned long logical_size_for_host = 0;    // the file size host will see(before dedup)
    unsigned long actual_size_in_disk = 0;      // the file size in disk(after dedup)
};
struct buffer_entry{
    off_t start_byte;   // which bytes to start
    uint16_t byte_cnt;  // how many bytes in buffer
    char *content = NULL;   // the content
};
struct file_handler_data{
    INUM_TYPE iNum;     // the inum of this file
    int fh;             // the file descriptor of the file
    char mode;          // the mode of open('r' | 'w')
    buffer_entry write_buf;  // the buffer use for write operation.
};

// message output macro
#ifdef DEBUG
#define DEBUG_MESSAGE(msg) std::cout << msg << std::endl
#else
#define DEBUG_MESSAGE(msg)
#endif
#define PRINT_MESSAGE(msg) std::cout << msg << std::endl
#define PRINT_WARNING(msg) std::cerr << msg << std::endl

#endif /* DEF_H */