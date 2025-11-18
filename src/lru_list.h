#include <unordered_map>

#include "def.h"

struct Node{
    Node(uint8_t read_count, INUM_TYPE iNum, uint32_t page_off): read_count(read_count), iNum(iNum), page_off(page_off) {}
    uint8_t read_count;
    INUM_TYPE iNum;
    uint32_t page_off;
    struct Node *prev = NULL;
    struct Node *next = NULL;
};

struct LRU_list{
    LRU_list(uint64_t max_len): max_len(max_len) {}
    std::unordered_map<uint64_t, Node *> hash_map;
    Node *head = NULL;
    Node *tail = NULL;
    uint64_t max_len;
    uint64_t cur_len = 0;
    void read(INUM_TYPE iNum, uint32_t page_off){
        uint64_t key = ((uint64_t)iNum << 32) | page_off;
        DEBUG_MESSAGE("  LRU read: iNum: " << iNum << " page_off: " << page_off << " key: " << key);
        auto it = hash_map.find(key);
        if (it == hash_map.end()){
            // not found
            DEBUG_MESSAGE(" LRU not found");
            Node *new_node = new Node(1, iNum, page_off);
            if (tail == NULL) [[unlikely]] {    // when the list is empty
                head = new_node;
                tail = new_node;
            }
            else{
                tail->next = new_node;
                new_node->prev = tail;
                tail = new_node;
            }
            hash_map[key] = new_node;
            cur_len += 1;
        }
        else{
            DEBUG_MESSAGE(" LRU found");
            Node *find_node = it->second;
            find_node->read_count += 1;
            while(find_node->prev != NULL and find_node->prev->read_count < find_node->read_count){
                Node *prev_node = find_node->prev;
                // swap neightbor link
                if (prev_node == head) [[unlikely]]
                    head = find_node;
                else
                    prev_node->prev->next = find_node;
                if (find_node == tail) [[unlikely]]
                    tail = prev_node;
                else
                    tail->next->prev = prev_node;
                // swap internal link
                Node *temp = prev_node->next;
                prev_node->next = find_node->next;
                find_node->next = temp;
                temp = prev_node->prev;
                prev_node->prev = find_node->prev;
                find_node->prev = temp;
            }
        }
    }

    Node *pop_head(){
        // caller need to delete node
        Node *target = head;
        if (target == tail) [[unlikely]] {
            head = NULL;
            tail = NULL;
        }
        else{
            head = head->next;
            head->prev = NULL;
        }
        cur_len -= 1;
        hash_map.erase(((uint64_t)target->iNum << 32) | target->page_off);
        return target;
    }

    bool empty(){
        return cur_len == 0;
    }
};