#include <iostream>
#include <limits.h>
#include <cstdint>
#include <vector>
#include <queue>

#ifndef DEF_H
#define DEF_H

#include "fastcdc.h"
#include "config.h"

/*
**  type define
*/
#define INUM_TYPE uint32_t
#define FP_TYPE std::string
#define PATH_TYPE std::string
#define FILE_HANDLER_INDEX_TYPE uint32_t
#define GROUP_IDX_TYPE uint32_t
#define OFF_T_MAX ((off_t)~((off_t)1 << (sizeof(off_t) * CHAR_BIT - 1)))

/*
**  metadata structure define
*/
struct chunk_addr{          // where this chunk is store in chunk store(first write place)
    INUM_TYPE iNum;         // first write file's iNum
    off_t offset;           // first write file's offset
    size_t length;          // chunk length
};
struct hash_store_entry{
    uint8_t ref_times;      // how many times this group is referenced
    std::vector<chunk_addr*> address_list;
};
struct mapping_table_entry{
    std::vector<GROUP_IDX_TYPE> group_idx;              // the group index of each "BLOCK"
    std::vector<bool> has_rewrite;                      // this group has been rewritten, so skip check next time
    std::vector<off_t> group_logical_offset;            // the logical start byte of every group in this file
    std::vector<off_t> group_virtual_offset;            // the virtual start byte of every group in this file
    std::vector<chunk_addr*> group_pos;                 // The real position of every Group
    GROUP_IDX_TYPE completed_link = 0;                  // how mant group has been linked to the virtual file
    size_t logical_size = 0;                            // the file size host will see(before dedup)
    size_t virtual_size = 0;                            // how many chunk have been reflink into virtual file(in bytes)
    size_t real_size = 0;                               // how many size has been used in real file
    std::unordered_map<off_t, off_t> remap;             // remap table (ori page offset -> rewrite file's page offset)
};
struct buffer_entry{        // write buffer
    off_t start_byte;       // which bytes to start
    uint16_t byte_cnt;      // how many bytes in buffer
    char *content = NULL;   // the content
};
struct chunkstore_entry{
    GROUP_IDX_TYPE group_idx;   // the group index of this chunk
    off_t logical_offset;       // logical offset of each chunk
    size_t length;              // length of this chunk
    char *content;              // the content of this chunk
};
struct file_handler_data{
    INUM_TYPE iNum;             // the inum of this file
    int fh;                     // the file descriptor of the file
    int csfh;                   // the file descriptor of chunk store
    char mode;                  // the mode of open('r' | 'w')
    buffer_entry write_buf;     // the buffer use for write operation.
    #ifdef CHUNK_CACHE_SIZE
    uint8_t chunk_count = 0;    // how many chunks in chunk store
    chunkstore_entry chunkstore[CHUNK_CACHE_SIZE];  // cache for chunk data
    #endif
};


/*
**  message output macro
*/
#ifdef DEBUG
#define DEBUG_MESSAGE(msg) std::cout << msg << std::endl    // only print debug message when "DEBUG" is being defined
#else
#define DEBUG_MESSAGE(msg)                                  // do nothing because "DEBUG" is not being defined
#endif
#define PRINT_MESSAGE(msg) std::cout << msg << std::endl    // print normal message
#define PRINT_WARNING(msg) std::cerr << msg << std::endl    // print warning or error message

/*
**  iNumber management
*/
std::queue<INUM_TYPE> free_iNum;
PATH_TYPE iNum_to_path[MAX_INODE_NUM];
std::unordered_map<PATH_TYPE, INUM_TYPE> path_to_iNum;

/*
**  file handler
*/
std::queue<FILE_HANDLER_INDEX_TYPE> free_file_handler;
file_handler_data file_handler[MAX_FILE_HANDLER];   // get iNum by file handler (faster than get by file path)

/*
**  fingerprint store
*/
std::unordered_map<FP_TYPE, hash_store_entry> fp_store;

/*
**  mapping table
*/
mapping_table_entry mapping_table[MAX_INODE_NUM];

/*
**  fastCDC chunker setting
*/
fcdc_ctx cdc_setting;

/*
**  file system stat record
*/
uint64_t total_write_size = 0;      // total size of writed file
uint64_t real_write_size = 0;       // total size of writed file after deduplication
uint64_t total_padding_size = 0;    // total size of padding disk
uint64_t host_read_size = 0;        // total size of host read
uint64_t fuse_read_size = 0;        // total size of fuse read
uint64_t remap_pread_count = 0;     // how many read I/O size go through remap table
uint64_t remap_req_count = 0;       // how many read req go through remap table
uint64_t read_req_align = 0;        // how many reqd req is align
uint64_t read_req_misalign = 0;     // how many reqd req is misalign
uint64_t read_req_frag = 0;         // how many reqd req is fragmentation

/*
**  lock
*/
std::shared_mutex create_file_mutex;    // the lock for create new file
std::shared_mutex fp_store_mutex;       // the lock for access fp_store
std::shared_mutex file_handler_mutex;   // the lock for allocate file handler and free file handler
std::shared_mutex chunker_mutex;        // the lock for access chunker
std::shared_mutex write_record_mutex;  // the lock for recording file system status
std::shared_mutex read_record_mutex;    // the lock for record host/fuse/ssd read size
std::shared_mutex mapping_table_mutex[MAX_INODE_NUM];           // per-file lock: shared for reads, exclusive for inline rewrite
std::shared_mutex mapping_table_remap_mutex[MAX_INODE_NUM];     // per-file lock: protect remap

#endif /* DEF_H */
