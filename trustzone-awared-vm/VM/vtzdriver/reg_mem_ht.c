#include "reg_mem_ht.h"

DEFINE_HASHTABLE(reg_mem_ht, HT_BITS); 
static DEFINE_SPINLOCK(ht_lock);

int add_reg_mem(struct reg_mem * p_reg) {
    struct reg_mem *tmp;
    unsigned long flags;
    spin_lock_irqsave(&ht_lock, flags);
    hash_for_each_possible(reg_mem_ht, tmp, node, p_reg->session_id) {
        if (tmp->session_id == p_reg->session_id) {
            spin_unlock_irqrestore(&ht_lock, flags);
            tloge("register mem has exists,session_id is %u\n", tmp->session_id);
                return -1;
        }
    }
    hash_add(reg_mem_ht, &p_reg->node, p_reg->session_id);
    spin_unlock_irqrestore(&ht_lock, flags);
    return 0;
}

struct reg_mem * find_reg_mem(uint32_t session_id) {
    struct reg_mem * p_reg;
    unsigned long flags;
    spin_lock_irqsave(&ht_lock, flags);
    hash_for_each_possible(reg_mem_ht, p_reg, node, session_id) {
        if (p_reg->session_id == session_id) {
            spin_unlock_irqrestore(&ht_lock, flags);
            tlogd("find success: id=%u\n", p_reg->session_id);
            return p_reg;
        }
    }
    spin_unlock_irqrestore(&ht_lock, flags);
    return NULL;
}

int del_reg_mem(uint32_t session_id) {
    struct reg_mem * p_reg;
    unsigned long flags;

    spin_lock_irqsave(&ht_lock, flags);
    hash_for_each_possible(reg_mem_ht, p_reg, node, session_id) {
        if (p_reg->session_id == session_id) {
            hash_del(&p_reg->node);
            spin_unlock_irqrestore(&ht_lock, flags);
            tlogd("delete success: id=%u\n", p_reg->session_id);
            kfree(p_reg);
            return 0;
        }
    }
    spin_unlock_irqrestore(&ht_lock, flags);
    tloge("delete failed: id=%u not found\n", session_id);
    return -1;
}