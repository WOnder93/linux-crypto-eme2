#ifndef _CRYPTO_BLOCKWALK_H
#define _CRYPTO_BLOCKWALK_H

#include <crypto/scatterwalk.h>

enum {
    BLOCKWALK_FLAGS_DIRECT_IN  = (1 << 0),
    BLOCKWALK_FLAGS_DIRECT_OUT = (1 << 1),
    BLOCKWALK_FLAGS_DIFF       = (1 << 2),
};

struct blockwalk {
    unsigned int blocksize, alignmask, bytesleft;
    int flags;
    struct scatter_walk sg_in, sg_out;
    u8 *buffer, *mapped_in, *mapped_out;
    unsigned int offset_in, offset_out;
    unsigned int limit_in, limit_out;
    unsigned int chunk_size;
};

void blockwalk_start(
        struct blockwalk *walk, unsigned int blocksize, unsigned int alignmask,
        u8 *buffer, struct scatterlist *sg_in, struct scatterlist *sg_out,
        unsigned int nbytes);

static inline unsigned int blockwalk_bytes_left(const struct blockwalk *walk)
{
    return walk->bytesleft;
}

static inline unsigned int blockwalk_chunk_size(const struct blockwalk *walk)
{
    return walk->chunk_size;
}

static inline void *blockwalk_chunk_in(const struct blockwalk *walk)
{
    return (walk->flags & BLOCKWALK_FLAGS_DIRECT_IN)
            ? walk->mapped_in + walk->offset_in : walk->buffer;
}

static inline void *blockwalk_chunk_out(const struct blockwalk *walk)
{
    return (walk->flags & BLOCKWALK_FLAGS_DIRECT_OUT)
            ? walk->mapped_out + walk->offset_out : walk->buffer;
}

void blockwalk_chunk_start(struct blockwalk *walk);
void blockwalk_chunk_finish(struct blockwalk *walk);

#endif /* _CRYPTO_BLOCKWALK_H */
