#ifndef _CRYPTO_BUFWALK_H
#define _CRYPTO_BUFWALK_H

#include <crypto/scatterwalk.h>

struct bufwalk {
    int out;
    unsigned int bufsize;
    unsigned int bytesleft;
    void *mapped;
    struct scatter_walk sg_walk;
};

static inline void bufwalk_start(
        struct bufwalk *walk, int out, unsigned int bufsize,
        struct scatterlist *sg, unsigned int nbytes)
{
    walk->out = out;
    walk->bufsize = bufsize;
    walk->bytesleft = nbytes;
    scatterwalk_start(&walk->sg_walk, sg);

    walk->mapped = scatterwalk_map(&walk->sg_walk) - walk->sg_walk.offset;
}

enum {
    BUFWALK_SKIP,
    BUFWALK_READ,
    BUFWALK_WRITE,
};

static inline unsigned int bufwalk_next(
        struct bufwalk *walk, int action, void *buffer)
{
    unsigned int size = walk->bytesleft >= walk->bufsize
            ? walk->bufsize : walk->bytesleft;
    unsigned int chunk, left = size;

    walk->bytesleft -= size;
    while (left != 0) {
        chunk = scatterwalk_clamp(&walk->sg_walk, left);
        switch(action) {
        case BUFWALK_READ:
            memcpy((u8 *)buffer + size - left,
                   walk->mapped + walk->sg_walk.offset,
                   chunk);
            break;
        case BUFWALK_WRITE:
            memcpy(walk->mapped + walk->sg_walk.offset,
                   (u8 *)buffer + size - left,
                   chunk);
            break;
        }

        scatterwalk_advance(&walk->sg_walk, chunk);
        left -= chunk;
        if (left + walk->bytesleft == 0) {
            scatterwalk_unmap(walk->mapped);
            scatterwalk_done(&walk->sg_walk, walk->out, 0);
        } else if (scatterwalk_pagelen(&walk->sg_walk) == 0) {
            scatterwalk_unmap(walk->mapped);
            scatterwalk_done(&walk->sg_walk, walk->out, 1);
            walk->mapped = scatterwalk_map(&walk->sg_walk)
                    - walk->sg_walk.offset;
        }
    }
    return size;
}

static inline unsigned int bufwalk_skip_next(struct bufwalk *walk)
{
    return bufwalk_next(walk, BUFWALK_SKIP, NULL);
}

static inline unsigned int bufwalk_read_next(
        struct bufwalk *walk, void *buffer)
{
    return bufwalk_next(walk, BUFWALK_READ, buffer);
}

static inline void bufwalk_write_next(struct bufwalk *walk, void *buffer)
{
    bufwalk_next(walk, BUFWALK_WRITE, buffer);
}

#endif // _CRYPTO_BUFWALK_H

