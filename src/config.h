#ifndef CONFIG_H
#define CONFIG_H

/*
**  pending setting
*/
// #define PENDING

/*
**  inline rewrite setting
*/
// #define INLINE_REWRITE
#define REWRITE_FILE_PATH "/rewrite"
#define PAGE_READ_LATENCY 35760     // samsung 970 pro
#define PAGE_WRITE_LATENCY 185000   // samsung 970 pro
#define INLINE_REWRITE_THRESHOLD (PAGE_WRITE_LATENCY / PAGE_READ_LATENCY)
#define INLINE_REWRITE_QUEUE_MAX 262144
#define ONESHOT_REWRITE_SIZE 131072     // 128KiB

/*
**  freq tracker setting
*/
#define DECAY_FACTOR 0.95
#define TIME_INTERVAL 60000000      // 1 minutes

/*
**  chunk cache setting
*/
// #define CHUNK_CACHE_SIZE 10      // how many chunk to cache in file handler(comment this line to disable chunk cache)

/*
**  DedupFS user setting
*/
#define BACKEND "./bak"             // where NVMeVirt or whatever test device is mounted
#define CHUNK_STORE "/chunk_store"  // where to store "chunk" it will be BACKEND/CHUNK_STORE
#define MAX_GROUP_SIZE 16384        // maximum size of CDC chunker
#define CHUNK_SIZE 4096             // average size of CDC chunker
#define SECTOR_SIZE 4096            // Btrfs minimum write size(normally 4096)
#define MAX_INODE_NUM 1048576       // maximum number of INODE(you should consider overflow of INUM_TYPE)
#define MAX_FILE_HANDLER 4096       // maximum number of file handler

#endif /* CONFIG_H */