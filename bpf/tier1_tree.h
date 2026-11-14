/* =========================================================================
 * AHHS-IDS: Tier 1 Lightweight Decision Tree (Auto-Generated via emlearn)
 * STRICT eBPF CONSTRAINTS APPLIED:
 * - Pure integer arithmetic (uint32_t features, no floating-point registers)
 * - All evaluation functions qualified with static __always_inline
 * - Shallow depth to guarantee verifier complexity < 1M instructions
 * ========================================================================= */

#ifndef TIER1_TREE_H
#define TIER1_TREE_H

#include <linux/types.h>

/* Tier 1 Actions */
#define TIER1_ACTION_PASS      0  /* Benign packet: immediately XDP_PASS */
#define TIER1_ACTION_DROP      1  /* Malicious packet: immediately XDP_DROP */
#define TIER1_ACTION_AMBIGUOUS 2  /* Ambiguous flow: pass to Tier 2 LRU tracking */

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
// !!! This file is generated using emlearn !!!

    #if defined(__bpf__) || defined(__BPF__)
typedef __s32 int32_t;
typedef __u32 uint32_t;
#else
#include <stdint.h>
#endif
    

static __always_inline int32_t tier1_tree_tree_0(const uint32_t *features, int32_t features_length) {
          if (features[3] < 890) {
              if (features[3] < 38) {
                  return 1;
              } else {
                  return 0;
              }
          } else {
              if (features[3] < 4722) {
                  return 1;
              } else {
                  if (features[3] < 20668) {
                      return 2;
                  } else {
                      return 1;
                  }
              }
          }
        }
        

static __always_inline int32_t tier1_tree_predict(const uint32_t *features, int32_t features_length) {

        int32_t votes[3] = {0,};
        int32_t _class = -1;

        _class = tier1_tree_tree_0(features, features_length); votes[_class] += 1;
    
        int32_t most_voted_class = -1;
        int32_t most_voted_votes = 0;
        for (int32_t i=0; i<3; i++) {

            if (votes[i] > most_voted_votes) {
                most_voted_class = i;
                most_voted_votes = votes[i];
            }
        }
        return most_voted_class;
    }
    

#if !defined(__bpf__) && !defined(__BPF__)
int tier1_tree_predict_proba(const uint32_t *features, int32_t features_length, float *out, int out_length) {

        int32_t _class = -1;

        for (int i=0; i<out_length; i++) {
            out[i] = 0.0f;
        }

        _class = tier1_tree_tree_0(features, features_length); out[_class] += 1.0f;
    
        // compute mean
        for (int i=0; i<out_length; i++) {
            out[i] = out[i] / 1;
        }
        return 0;
    }
#endif /* !__BPF__ */
#pragma clang diagnostic pop

#endif /* TIER1_TREE_H */
