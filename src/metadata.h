#include <shared_mutex>
#include <mutex>

#include "def.h"

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
        INUM_TYPE new_iNum = free_iNum.front();
        free_iNum.pop();
        path_to_iNum[path_str] = new_iNum;
        iNum_to_path[new_iNum] = path_str;
        return new_iNum;
    }
}

inline PATH_TYPE get_path(INUM_TYPE iNum){
    std::shared_lock<std::shared_mutex> shared_create_file_lock(create_file_mutex);      // make sure nobody is creating new file at the same time
    return iNum_to_path[iNum];
}

inline FILE_HANDLER_INDEX_TYPE get_file_handler(){
    std::unique_lock<std::shared_mutex> unique_file_handler_lock(file_handler_mutex);   // lock for allocating new file handler
    if (free_file_handler.empty()){
        PRINT_WARNING("dedupfs: run out of file handlers");
        return -1;
    }
    FILE_HANDLER_INDEX_TYPE new_file_handler_index = free_file_handler.front();
    free_file_handler.pop();
    return new_file_handler_index;
}

inline void release_file_handler(FILE_HANDLER_INDEX_TYPE file_handler_index){
    if (file_handler_index < 0 || file_handler_index >= MAX_FILE_HANDLER) return;
    std::unique_lock<std::shared_mutex> unique_file_handler_lock(file_handler_mutex);    // lock for freeing file handler
    free_file_handler.push(file_handler_index);
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
        #ifdef CHUNK_CACHE_SIZE
        file_handler[file_handler_index].chunk_count = 0;
        for (int i = 0; i < CHUNK_CACHE_SIZE; i++)
            file_handler[file_handler_index].chunkstore[i].content = new char[MAX_GROUP_SIZE];
        #endif
    }
}