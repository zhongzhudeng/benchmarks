#ifndef QMAN_H_
#define QMAN_H_

#include <stdlib.h>
#include <unistd.h>

#include <utils.h>

#define QMAN_SET_RATE     (1 << 0)
#define QMAN_SET_MAXCHUNK (1 << 1)
#define QMAN_SET_AVAIL    (1 << 3)
#define QMAN_ADD_AVAIL    (1 << 4)

#define BATCH_SIZE 16
#define QMAN_SKIPLIST_LEVELS 4

struct qman_thread {
  /************************************/
  /* read-only */
  struct queue *queues;

  /************************************/
  /* modified by owner thread */
  uint32_t head_idx[QMAN_SKIPLIST_LEVELS];
  uint32_t ts_real;
  uint32_t ts_virtual;
  struct utils_rng rng;
};

int qman_thread_init(struct qman_thread *t, uint64_t core_id);
uint32_t qman_timestamp(uint64_t cycles);
int qman_poll(struct qman_thread *t, unsigned num, unsigned *q_ids,
    uint32_t *q_bytes);
int qman_set(struct qman_thread *t, uint32_t id, uint32_t rate, 
    uint32_t avail, uint16_t max_chunk, uint8_t flags);

#endif /* ndef QMAN_H_ */