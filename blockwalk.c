#include "blockwalk.h"

static u8 *scatterwalk_map_page(struct scatter_walk *walk)
{
    return (u8 *)kmap_atomic(scatterwalk_page(walk));
}

static unsigned int scatterwalk_offset_in_page(struct scatter_walk *walk)
{
    return walk->offset & ~PAGE_MASK;
}

static int scatterwalk_samepage(
        struct scatter_walk *in, struct scatter_walk *out)
{
    return scatterwalk_page(in) == scatterwalk_page(out);
}

void blockwalk_start(
        struct blockwalk *walk, unsigned int blocksize, unsigned int alignmask,
        u8 *buffer, struct scatterlist *sg_in, struct scatterlist *sg_out,
        unsigned int nbytes)
{
    walk->blocksize = blocksize;
    walk->alignmask = alignmask;
    walk->bytesleft = nbytes;
    walk->flags = 0;
    scatterwalk_start(&walk->sg_in, sg_in);
    scatterwalk_start(&walk->sg_out, sg_out);
    walk->buffer = (u8 *)buffer;

    walk->mapped_in = scatterwalk_map_page(&walk->sg_in);
    walk->mapped_out = walk->mapped_in;
    if (!scatterwalk_samepage(&walk->sg_in, &walk->sg_out)) {
        walk->flags |= BLOCKWALK_FLAGS_DIFF;
        walk->mapped_out = scatterwalk_map_page(&walk->sg_out);
    }
    walk->offset_in     = scatterwalk_offset_in_page(&walk->sg_in);
    walk->offset_out    = scatterwalk_offset_in_page(&walk->sg_out);
    walk->limit_in      = walk->offset_in  + scatterwalk_pagelen(&walk->sg_in);
    walk->limit_out     = walk->offset_out + scatterwalk_pagelen(&walk->sg_out);
    walk->chunk_size = 0;
}
EXPORT_SYMBOL_GPL(blockwalk_start);

static void blockwalk_advance_in(
        struct blockwalk *walk, unsigned int size, unsigned int more)
{
    if (!more) {
        if (walk->flags & BLOCKWALK_FLAGS_DIFF) {
            scatterwalk_unmap(walk->mapped_in);
        } else {
            walk->flags |= BLOCKWALK_FLAGS_DIFF;
        }
        return;
    }

    scatterwalk_advance(&walk->sg_in, size);
    walk->offset_in += size;
    if (walk->offset_in >= walk->limit_in) {
        if (walk->flags & BLOCKWALK_FLAGS_DIFF) {
            scatterwalk_unmap(walk->mapped_in);
        }
        scatterwalk_done(&walk->sg_in, 0, more);
        walk->flags |= BLOCKWALK_FLAGS_DIFF;
        walk->mapped_in = scatterwalk_map_page(&walk->sg_in);
        walk->offset_in = scatterwalk_offset_in_page(&walk->sg_in);
        walk->limit_in = walk->offset_in  + scatterwalk_pagelen(&walk->sg_in);
    }
}

static void blockwalk_advance_out(
        struct blockwalk *walk, unsigned int size, unsigned int more)
{
    if (!more) {
        if (walk->flags & BLOCKWALK_FLAGS_DIFF) {
            scatterwalk_unmap(walk->mapped_out);
        } else {
            walk->flags |= BLOCKWALK_FLAGS_DIFF;
        }
        return;
    }

    scatterwalk_advance(&walk->sg_out, size);
    walk->offset_out += size;
    if (walk->offset_out >= walk->limit_out) {
        if (walk->flags & BLOCKWALK_FLAGS_DIFF) {
            scatterwalk_unmap(walk->mapped_out);
        }
        scatterwalk_done(&walk->sg_out, 1, more);
        if (scatterwalk_samepage(&walk->sg_in, &walk->sg_out)) {
            walk->mapped_out = walk->mapped_in;
            walk->flags &= ~BLOCKWALK_FLAGS_DIFF;
        } else {
            walk->mapped_out = scatterwalk_map_page(&walk->sg_out);
            walk->flags |= BLOCKWALK_FLAGS_DIFF;
        }
        walk->offset_out = scatterwalk_offset_in_page(&walk->sg_out);
        walk->limit_out = walk->offset_out + scatterwalk_pagelen(&walk->sg_out);
    }
}

void blockwalk_next_chunk(struct blockwalk *walk)
{
    unsigned int size, size_in, size_out;
    u8 *tmp;

    // advance the buffers if in direct mode:
    if (unlikely(walk->flags & BLOCKWALK_FLAGS_DIRECT_IN)) {
        blockwalk_advance_in(walk, walk->chunk_size, walk->bytesleft);
    }

    if (unlikely(walk->flags & BLOCKWALK_FLAGS_DIRECT_OUT)) {
        blockwalk_advance_out(walk, walk->chunk_size, walk->bytesleft);
    } else {
        // write the last chunk if in indirect mode:
        tmp = walk->buffer;
        while (walk->chunk_size != 0) {
            size = scatterwalk_clamp(&walk->sg_out, walk->chunk_size);
            memcpy(walk->mapped_out + walk->offset_out, tmp, size);
            tmp += size;
            walk->chunk_size -= size;

            blockwalk_advance_out(
                        walk, size, walk->chunk_size + walk->bytesleft);
        }
    }

    walk->flags |= BLOCKWALK_FLAGS_DIRECT_IN;
    walk->flags |= BLOCKWALK_FLAGS_DIRECT_OUT;

    size_in  = scatterwalk_pagelen(&walk->sg_in);
    size_out = scatterwalk_pagelen(&walk->sg_out);

    if (unlikely(!scatterwalk_aligned(&walk->sg_in, walk->alignmask))) {
        walk->flags &= ~BLOCKWALK_FLAGS_DIRECT_IN;
        size_in = min(size_in, walk->blocksize);
    }
    if (unlikely(!scatterwalk_aligned(&walk->sg_out, walk->alignmask))) {
        walk->flags &= ~BLOCKWALK_FLAGS_DIRECT_OUT;
        size_out = min(size_out, walk->blocksize);
    }

    size = min(size_in, size_out);
    if (size < walk->bytesleft) {
        size = size & ~(walk->blocksize - 1);

        if (unlikely(size_in < walk->blocksize)) {
            walk->flags &= ~BLOCKWALK_FLAGS_DIRECT_IN;
            size = walk->blocksize;
        }

        if (unlikely(size_out < walk->blocksize)) {
            walk->flags &= ~BLOCKWALK_FLAGS_DIRECT_OUT;
            size = walk->blocksize;
        }
    } else {
        size = walk->bytesleft;
    }
    walk->chunk_size = size;
    walk->bytesleft -= size;

    if (unlikely(!(walk->flags & BLOCKWALK_FLAGS_DIRECT_IN))) {
        tmp = walk->buffer;
        do {
            memcpy(tmp, walk->mapped_in + walk->offset_in, size_in);
            tmp += size_in;
            size -= size_in;
            blockwalk_advance_in(walk, size_in, size + walk->bytesleft);

            size_in = scatterwalk_clamp(&walk->sg_in, size);
        } while (size != 0);
    }
}
EXPORT_SYMBOL_GPL(blockwalk_next_chunk);
