#include <iostream>
#include <vector>
#include <cstdint>

#ifndef DEF_H
#define DEF_H

// pending
// #define PENDING

// record page read latehcy
// #define RECORD_LATENCY
#define RECORD_LATENCY_PATH "/home/johnnychang/result/fuse.lat"
#define RECORD_FRAG_PATH "/home/johnnychang/result/fuse.frag"

// DedupFS user setting
#define BACKEND "/home/johnnychang/Projects/DedupFS/bak"
#define CHUNK_STORE "/chunk_store"
#define MAX_GROUP_SIZE 16384
#define CHUNK_SIZE 4096
#define SSD_ONESHOT 4096
#define SECTOR_SIZE 4096        // Btrfs minimum write size(normally 4096)
#define CHUNK_CACHE_SIZE 5      // how many chunk to cache in file handler(comment this line to disable chunk cache)

// don't change it!
#define MAX_INODE_NUM 1048576
#define MAX_FILE_HANDLER 4096

// type define
#define INUM_TYPE uint32_t
#define FP_TYPE std::string
#define PATH_TYPE std::string
#define FILE_HANDLER_INDEX_TYPE uint32_t
#define GROUP_IDX_TYPE uint32_t

// struct define
struct chunk_addr{
    INUM_TYPE iNum;
    off_t offset;
    size_t length;
};
struct hash_store_entry{
    uint8_t ref_times;      // how many times this group is referenced
    chunk_addr *address;
};
struct mapping_table_entry{
    std::vector<GROUP_IDX_TYPE> group_idx;              // the group index of each "BLOCK"
    std::vector<off_t> group_logical_offset;            // the logical start byte of every group in this file
    std::vector<off_t> group_virtual_offset;            // the virtual start byte of every group in this file
    std::vector<chunk_addr*> group_pos;                 // The real position of every Group
    GROUP_IDX_TYPE completed_link = 0;                  // how mant group has been linked to the virtual file
    size_t logical_size = 0;                            // the file size host will see(before dedup)
    size_t virtual_size = 0;                            // how many chunk have been reflink into virtual file(in bytes)
    size_t real_size = 0;                               // how many size has been used in real file
};
struct buffer_entry{
    off_t start_byte;       // which bytes to start
    uint16_t byte_cnt;      // how many bytes in buffer
    char *content = NULL;   // the content
};

struct chunkstore_entry{
    GROUP_IDX_TYPE group_idx;  // the group index of this chunk
    off_t logical_offset;   // logical offset of each chunk
    size_t length;          // length of this chunk
    char *content;          // the content of this chunk
};

struct file_handler_data{
    INUM_TYPE iNum;             // the inum of this file
    int fh;                     // the file descriptor of the file
    int csfh;                   // the file descriptor of chunk store
    char mode;                  // the mode of open('r' | 'w')
    buffer_entry write_buf;     // the buffer use for write operation.
    #ifdef CHUNK_CACHE_SIZE
    uint8_t chunk_count = 0; // how many chunks in chunk store
    chunkstore_entry chunkstore[CHUNK_CACHE_SIZE]; // cache for chunk data
    #endif
};

#ifdef RECORD_LATENCY
struct each_page_read_bandwidth{
    std::vector<double> lat;
    std::vector<uint32_t> count;
};
#endif

// message output macro
#ifdef DEBUG
#define DEBUG_MESSAGE(msg) std::cout << msg << std::endl
#else
#define DEBUG_MESSAGE(msg)
#endif
#define PRINT_MESSAGE(msg) std::cout << msg << std::endl
#define PRINT_WARNING(msg) std::cerr << msg << std::endl

#endif /* DEF_H */