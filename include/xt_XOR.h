#ifndef _XT_XOR_H
#define _XT_XOR_H

#define XT_XOR_MAX_KEY_SIZE 256

struct xt_xor_info {
    uint32_t first;
    uint32_t key_len;
    unsigned char key[XT_XOR_MAX_KEY_SIZE];
};

#endif /* _XT_XOR_H */
