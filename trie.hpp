#pragma once

#ifndef __TRIE_HPP__
#define __TRIE_HPP__

#include "router.hpp"

struct TrieNode
{
    TrieNode *child[2];
    route_table_entry *route;

    TrieNode()
        : route(nullptr)
    {
        child[0] = child[1] = nullptr;
    }
};

size_t get_prefix_length(uint32_t mask)
{
    size_t prefix_len = 0;
    uint32_t mask_be = ntohl(mask);

    for (ssize_t i = 31; i >= 0; --i)
    {
        if ((mask_be >> i) & 1)
            prefix_len++;
        else
            break;
    }
    return prefix_len;
}

void trie_insert(TrieNode *root, route_table_entry *rt)
{
    size_t prefix_len = get_prefix_length(rt->mask);
    TrieNode *node = root;

    uint32_t prefix_be = ntohl(rt->prefix);
    for (size_t i = 0; i < prefix_len; ++i)
    {
        size_t bit = (prefix_be >> (31 - i)) & 1;
        if (!node->child[bit])
        {
            node->child[bit] = new TrieNode();
        }
        node = node->child[bit];
    }
    node->route = rt;
}

void build_trie(TrieNode *&root, route_table_entry *rtable, size_t num_entries)
{
    root = new TrieNode();
    for (size_t i = 0; i < num_entries; ++i)
    {
        trie_insert(root, &rtable[i]);
    }
}

route_table_entry *lookup(TrieNode *root, uint32_t ip_address)
{
    TrieNode *node = root;
    route_table_entry *best_match = nullptr;

    uint32_t ip_be = ntohl(ip_address);
    for (size_t i = 0; i < 32 && node; ++i)
    {
        if (node->route)
            best_match = node->route;
        int bit = (ip_be >> (31 - i)) & 1;
        node = node->child[bit];
    }
    return best_match;
}

void delete_trie(TrieNode *root)
{
    if (!root)
        return;
    delete_trie(root->child[0]);
    delete_trie(root->child[1]);
    delete root;
}

#endif
