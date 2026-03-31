#include <unordered_map>
#include <cstdint>
#include <chrono>
#include <cmath>

#include "def.h"

using TimePoint = std::chrono::system_clock::time_point;
using ScoreType = uint32_t;

class FreqTracker{
public:
    FreqTracker() {}
    ScoreType read(uint32_t LPA){
        auto it = score_table.find(LPA);
        TimePoint cur_timestamp = std::chrono::high_resolution_clock::now();
        if (it == score_table.end()){
            score_table[LPA] = {1, cur_timestamp};
            return 1;
        }
        else{
            auto entry = it->second;
            int64_t elapsed = std::chrono::duration_cast<std::chrono::microseconds>(cur_timestamp - entry.second).count();
            entry.first = entry.first * std::pow(DECAY_FACTOR, (float)elapsed / TIME_INTERVAL) + 1;
            entry.second = cur_timestamp;
            return entry.first;
        }
    }
private:
    std::unordered_map<int, std::pair<ScoreType, TimePoint>> score_table;
};