#ifndef INC_BL_TRUST_H_
#define INC_BL_TRUST_H_

#include "main.h"
#include "memory_map.h"
#include <stdint.h>

/* Persistent boot state stored in RTC backup registers (STM32F072: BKP0R..BKP4R).
  This avoids relying on .noinit RAM and survives NVIC_SystemReset() and watchdog resets. */
#define BL_BKP_SIGNATURE              (0x4F57424CU) /* 'OWBL' */
#define BL_BKP_REQ_DFU_MAGIC          (0x21554644U) /* 'DFU!' */

#define BL_BKP_STATE_FORCE_DFU        (1U << 0U)
#define BL_BKP_STATE_BOOT_IN_PROGRESS (1U << 1U)
#define BL_BKP_STATE_BOOT_OK          (1U << 2U)
#define BL_BKP_STATE_FAILCOUNT_SHIFT  (8U)
#define BL_BKP_STATE_FAILCOUNT_MASK   (0xFFU << BL_BKP_STATE_FAILCOUNT_SHIFT)

#define BL_BOOT_FAIL_THRESHOLD        (2U)
#define BL_BKP_AUTH_CACHE_XOR         (0xA5964C3DU)

#define BL_TRUST_HMAC_KEY_BYTES       (32U)

/* Replace with a device-unique secret key in production provisioning. */
static const uint8_t g_bl_trust_hmac_key[BL_TRUST_HMAC_KEY_BYTES] = {
  0x17U, 0xB2U, 0x05U, 0x19U, 0x59U, 0x0CU, 0xFDU, 0x78U,
  0x10U, 0x4FU, 0xCEU, 0x50U, 0x94U, 0x91U, 0x34U, 0x5FU,
  0x36U, 0xEFU, 0xF0U, 0x47U, 0xD0U, 0x32U, 0x9EU, 0x78U,
  0xACU, 0x65U, 0x06U, 0x51U, 0xE6U, 0x35U, 0xB8U, 0x7EU,
};

typedef struct
{
  uint32_t key_id;
  uint8_t public_key[64];
} bl_pubkey_entry_t;

/* Replace with production public keys provisioned through your secure release process. */
static const bl_pubkey_entry_t g_bl_pubkeys[] = {
  {
    1U,
    {
      0x74U, 0x6EU, 0xE7U, 0xA0U, 0xDDU, 0xC9U, 0x53U, 0x4FU,
      0x7BU, 0xF8U, 0x9BU, 0xD5U, 0xD5U, 0xA0U, 0xEFU, 0xE9U,
      0xF2U, 0xDAU, 0xC5U, 0xBFU, 0x0CU, 0x1CU, 0xFEU, 0x46U,
      0x29U, 0x47U, 0xB7U, 0xD9U, 0x36U, 0xDBU, 0x26U, 0x0CU,
      0x02U, 0xBCU, 0xB6U, 0x3BU, 0x34U, 0xE7U, 0x06U, 0x78U,
      0xA8U, 0xF5U, 0x14U, 0x33U, 0x75U, 0xCDU, 0xD0U, 0xF5U,
      0xDFU, 0x9CU, 0x20U, 0x29U, 0xC2U, 0x43U, 0x1BU, 0xD9U,
      0x41U, 0x12U, 0x52U, 0x90U, 0x16U, 0xB8U, 0x90U, 0x94U,
    },
  },
};

typedef struct {
  uint8_t por;
  uint8_t pin;
  uint8_t sft;
  uint8_t iwdg;
  uint8_t wwdg;
} bl_reset_flags_t;

void bl_bootstate_init(void);
uint8_t bl_auth_cache_match(uint32_t fw_crc32);
void bl_auth_cache_store(uint32_t fw_crc32);
void bl_auth_cache_clear(void);
uint32_t bl_bootstate_set_failcount(uint32_t state, uint8_t count);
const fw_metadata_t *bl_metadata_ptr(void);
uint8_t bl_app_stack_pointer_sane(void);
uint8_t bl_app_reset_vector_sane(void);
bl_reset_flags_t bl_read_and_clear_reset_flags(void);
const uint8_t *bl_find_public_key(uint32_t key_id);
void bl_bkp_enable(void);
void bl_clear_boot_state_cold(const bl_reset_flags_t *reset_flags);
uint8_t bl_should_enter_dfu(const bl_reset_flags_t *reset_flags,
    uint8_t meta_valid,
    const fw_metadata_t *meta);
void bl_mark_boot_in_progress(void);
void bl_clear_boot_in_progress(void);
uint8_t bl_consttime_equal(const uint8_t *a, const uint8_t *b, uint32_t len);
void bl_hmac_sha256(const uint8_t *key,
    uint32_t key_len,
    const uint8_t *msg,
    uint32_t msg_len,
    uint8_t out[32]);
uint8_t firmware_trust_tag_valid(const fw_metadata_t *meta);
uint8_t firmware_signature_valid(const fw_metadata_t *meta);
uint8_t firmware_metadata_valid(const fw_metadata_t *meta);
void firmware_sha256(uint32_t fw_addr, uint32_t fw_len, uint8_t out[32]);

#endif // INC_BL_TRUST_H_