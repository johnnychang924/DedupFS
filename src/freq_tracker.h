#include <unordered_map>
#include <cstdint>
#include <chrono>
#include <cmath>
#include <shared_mutex>
#ifdef RECORD_PAGE_SCORE
#include <algorithm>
#include <fstream>
#include <vector>
#endif

#include "def.h"

using TimePoint = std::chrono::high_resolution_clock::time_point;
using ScoreType = float;

class FreqTracker{
public:
    FreqTracker() {}
    ScoreType read(uint64_t LPA){
        std::unique_lock<std::shared_mutex> lock(mutex);
        auto it = score_table.find(LPA);
        TimePoint cur_timestamp = std::chrono::high_resolution_clock::now();
        if (it == score_table.end()){
            score_table[LPA] = {1, cur_timestamp};
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
    void delete_LPA(uint64_t LPA){
        std::unique_lock<std::shared_mutex> lock(mutex);
        score_table.erase(LPA);
    }
    #ifdef RECORD_PAGE_SCORE
    void dump_scores(const char* path){
        std::unique_lock<std::shared_mutex> lock(mutex);
        std::vector<std::pair<uint64_t, ScoreType>> entries;
        entries.reserve(score_table.size());
        for (const auto& kv : score_table)
            entries.push_back({kv.first, kv.second.first});
        std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b){ return a.second < b.second; });
        std::ofstream out(path);
        for (const auto& e : entries)
            out << e.first << " " << e.second << "\n";
    }
    #endif
private:
    std::unordered_map<uint64_t, std::pair<ScoreType, TimePoint>> score_table;
    std::shared_mutex mutex;
};