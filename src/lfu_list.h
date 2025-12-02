#include <unordered_map>
#include <map>
#include <list>
#include <vector>
#include <shared_mutex>
#include <cstdint>
#include <mutex>

class LFUList {
public:
    using LPA = uint64_t;

    // Node tracked for each LPA
    struct Entry {
        int freq;
        std::list<LPA>::iterator it;
    };

    // freq -> list of LPAs
    //std::unordered_map<int, std::list<LPA>> freq_buckets;
    std::vector<std::list<LPA>> freq_buckets;

    // LPA -> Entry
    std::unordered_map<LPA, Entry> table;

    // thread safety
    mutable std::shared_mutex mtx;

public:
    // Initialize freq_buckets
    LFUList(){ freq_buckets.resize(2); }
    // Increase frequency count for an LPA
    void touch(LPA lpa) {
        std::unique_lock lock(mtx);

        auto it = table.find(lpa);

        if (it == table.end()) {
            // New LPA, frequency = 1
            freq_buckets[1].push_front(lpa);
            table[lpa] = {1, freq_buckets[1].begin()};
            return;
        }

        // existing LPA
        int old_freq = it->second.freq;
        auto old_it = it->second.it;

        // Remove from old bucket
        freq_buckets[old_freq].erase(old_it);

        // Add to new bucket
        int new_freq = old_freq + 1;
        ensureBucketExists(new_freq);
        freq_buckets[new_freq].push_front(lpa);

        // Update entry
        it->second.freq = new_freq;
        it->second.it = freq_buckets[new_freq].begin();
    }

    // Get top K most frequently accessed LPAs
    std::vector<LPA> topK(size_t K) const {
        std::shared_lock lock(mtx);

        std::vector<LPA> result;
        result.reserve(K);

        // iterate from highest freq to low
        for (auto rit = freq_buckets.rbegin(); rit != freq_buckets.rend(); ++rit) {
            for (const auto &lpa : *rit) {
                result.push_back(lpa);
                if (result.size() == K)
                    return result;
            }
        }

        return result;
    }

    // Remove all entries (optional)
    void clear() {
        std::unique_lock lock(mtx);
        freq_buckets.clear();
        freq_buckets.resize(2);
        table.clear();
    }

private:
    // Ensures freq_buckets[freq] exists
    inline void ensureBucketExists(uint32_t freq) {
        if (freq >= freq_buckets.size()) {
            freq_buckets.resize(freq + 1);
        }
    }
};
