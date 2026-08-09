#include <unordered_map>
#include <cstdint>
#include <chrono>
#include <mutex>

#include "def.h"

using TimePoint = std::chrono::high_resolution_clock::time_point;
using ScoreType = float;

/*
**  Track the hotness of each "Logical page" of file
*/
class FreqTracker{
public:
    FreqTracker() {}
    ScoreType read(uint32_t iNum, uint32_t LPA){
        uint64_t key = ((uint64_t)iNum << 32) | LPA;
        std::lock_guard<std::mutex> lock(write_lock);
        auto it = score_table.find(key);
        TimePoint cur_timestamp = std::chrono::high_resolution_clock::now();
        if (it == score_table.end()){
            score_table[key] = {1, cur_timestamp};
            return 1;
        }
        else{
            auto& entry = it->second;
            int64_t elapsed = std::chrono::duration_cast<std::chrono::microseconds>(cur_timestamp - entry.second).count();
            entry.first = entry.first * std::pow(DECAY_FACTOR, (float)elapsed / TIME_INTERVAL) + 1;
            entry.second = cur_timestamp;
            return entry.first;
        }
    }
    void delete_LPA(uint32_t iNum, uint32_t LPA){
        uint64_t key = ((uint64_t)iNum << 32) | LPA;
        std::lock_guard<std::mutex> lock(write_lock);
        score_table.erase(key);
    }
private:
    std::unordered_map<uint64_t, std::pair<ScoreType, TimePoint>> score_table;
    std::mutex write_lock;
};