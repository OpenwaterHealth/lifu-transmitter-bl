#include "bl_trust.h"
#include "memory_map.h"
#include "sha256.h"
#include "uECC.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

const fw_metadata_t *bl_metadata_ptr(void)
{
  return (const fw_metadata_t *)METADATA_ADDRESS;
}

uint8_t bl_app_stack_pointer_sane(void)
{
  uint32_t app_sp = *(__IO uint32_t *)APPLICATION_ADDRESS;
  return ((app_sp & 0x2FFE0000U) == 0x20000000U) ? 1U : 0U;
}

uint8_t bl_app_reset_vector_sane(void)
{
  uint32_t app_rv = *(__IO uint32_t *)(APPLICATION_ADDRESS + 4U);
  uint32_t app_rv_addr = app_rv & (~1UL);
  uint32_t app_end = APPLICATION_ADDRESS + APPLICATION_MAX_SIZE;

  /* Cortex-M must branch to Thumb code (LSB set), and entry address must be in app range. */
  if ((app_rv & 0x1U) == 0U)
  {
    return 0U;
  }

  if ((app_rv_addr < APPLICATION_ADDRESS) || (app_rv_addr >= app_end))
  {
    return 0U;
  }

  return 1U;
}

bl_reset_flags_t bl_read_and_clear_reset_flags(void)
{
  bl_reset_flags_t flags;

  flags.por = (__HAL_RCC_GET_FLAG(RCC_FLAG_BORRST) != RESET) ? 1U : 0U;
  flags.pin = (__HAL_RCC_GET_FLAG(RCC_FLAG_PINRST) != RESET) ? 1U : 0U;
  flags.sft = (__HAL_RCC_GET_FLAG(RCC_FLAG_SFTRST) != RESET) ? 1U : 0U;
  flags.iwdg = (__HAL_RCC_GET_FLAG(RCC_FLAG_IWDGRST) != RESET) ? 1U : 0U;
  flags.wwdg = (__HAL_RCC_GET_FLAG(RCC_FLAG_WWDGRST) != RESET) ? 1U : 0U;

  __HAL_RCC_CLEAR_RESET_FLAGS();
  return flags;
}

const uint8_t *bl_find_public_key(uint32_t key_id)
{
  uint32_t i;

  for (i = 0U; i < (uint32_t)(sizeof(g_bl_pubkeys) / sizeof(g_bl_pubkeys[0])); ++i)
  {
    if (g_bl_pubkeys[i].key_id == key_id)
    {
      return g_bl_pubkeys[i].public_key;
    }
  }

  return NULL;
}

void bl_bkp_enable(void)
{
  /* Backup domain write access. */
  __HAL_RCC_PWR_CLK_ENABLE();
  HAL_PWR_EnableBkUpAccess();

  /* Ensure RTC domain is clocked so BKP registers are accessible.
     Only configure RTC clock source if RTC is not already enabled. */
  if ((RCC->BDCR & RCC_BDCR_RTCEN) == 0U)
  {
    uint32_t rtcsel = (RCC->BDCR & RCC_BDCR_RTCSEL);
    if (rtcsel == 0U)
    {
      /* Select LSI for RTC if no source configured.
         On STM32F0: RTCSEL=10b selects LSI -> RCC_BDCR_RTCSEL_1. */
      MODIFY_REG(RCC->BDCR, RCC_BDCR_RTCSEL, RCC_BDCR_RTCSEL_1);
    }
    SET_BIT(RCC->BDCR, RCC_BDCR_RTCEN);
  }
}

void bl_bootstate_init(void)
{
  bl_bkp_enable();

  if (RTC->BKP0R != BL_BKP_SIGNATURE)
  {
    RTC->BKP0R = BL_BKP_SIGNATURE;
    RTC->BKP1R = 0U; /* request */
    RTC->BKP2R = 0U; /* state + counters */
    RTC->BKP3R = 0U; /* last bad fw crc */
    RTC->BKP4R = 0U; /* auth cache */
  }
}

uint8_t bl_bootstate_get_failcount(uint32_t state)
{
  return (uint8_t)((state & BL_BKP_STATE_FAILCOUNT_MASK) >> BL_BKP_STATE_FAILCOUNT_SHIFT);
}

uint8_t bl_auth_cache_match(uint32_t fw_crc32)
{
  uint32_t cache = RTC->BKP4R;

  if (cache == 0U)
  {
    return 0U;
  }

  return (((cache ^ BL_BKP_AUTH_CACHE_XOR) == fw_crc32) ? 1U : 0U);
}

void bl_auth_cache_store(uint32_t fw_crc32)
{
  RTC->BKP4R = fw_crc32 ^ BL_BKP_AUTH_CACHE_XOR;
}

void bl_auth_cache_clear(void)
{
  RTC->BKP4R = 0U;
}

uint32_t bl_bootstate_set_failcount(uint32_t state, uint8_t count)
{
  uint32_t s = state & ~BL_BKP_STATE_FAILCOUNT_MASK;
  s |= ((uint32_t)count << BL_BKP_STATE_FAILCOUNT_SHIFT) & BL_BKP_STATE_FAILCOUNT_MASK;
  return s;
}

uint8_t bl_consttime_equal(const uint8_t *a, const uint8_t *b, uint32_t len)
{
  uint8_t diff = 0U;
  uint32_t i;

  for (i = 0U; i < len; ++i)
  {
    diff |= (uint8_t)(a[i] ^ b[i]);
  }

  return (diff == 0U) ? 1U : 0U;
}

void bl_hmac_sha256(const uint8_t *key,
    uint32_t key_len,
    const uint8_t *msg,
    uint32_t msg_len,
    uint8_t out[32])
{
  uint8_t key_block[64];
  uint8_t ipad[64];
  uint8_t opad[64];
  uint8_t inner_hash[32];
  sha256_ctx_t ctx;
  uint32_t i;

  memset(key_block, 0, sizeof(key_block));

  if (key_len > sizeof(key_block))
  {
    sha256_init(&ctx);
    sha256_update(&ctx, key, key_len);
    sha256_final(&ctx, key_block);
  }
  else
  {
    memcpy(key_block, key, key_len);
  }

  for (i = 0U; i < 64U; ++i)
  {
    ipad[i] = (uint8_t)(key_block[i] ^ 0x36U);
    opad[i] = (uint8_t)(key_block[i] ^ 0x5CU);
  }

  sha256_init(&ctx);
  sha256_update(&ctx, ipad, sizeof(ipad));
  sha256_update(&ctx, msg, msg_len);
  sha256_final(&ctx, inner_hash);

  sha256_init(&ctx);
  sha256_update(&ctx, opad, sizeof(opad));
  sha256_update(&ctx, inner_hash, sizeof(inner_hash));
  sha256_final(&ctx, out);
}

uint8_t firmware_trust_tag_valid(const fw_metadata_t *meta)
{
  uint8_t expected[32];
  uint32_t tag_input_len = (uint32_t)((const uint8_t *)&meta->trust_tag - (const uint8_t *)meta);

  bl_hmac_sha256(g_bl_trust_hmac_key,
      BL_TRUST_HMAC_KEY_BYTES,
      (const uint8_t *)METADATA_ADDRESS,
      tag_input_len,
      expected);

  return bl_consttime_equal(expected, meta->trust_tag, (uint32_t)sizeof(expected));
}

uint8_t firmware_signature_valid(const fw_metadata_t *meta)
{
  const uint8_t *public_key = bl_find_public_key(meta->key_id);
  uint8_t digest[32];

  if (public_key == NULL)
  {
    return 0U;
  }

  firmware_sha256(meta->fw_address, meta->fw_length, digest);

  return (uECC_verify(public_key,
      digest,
      sizeof(digest),
      meta->signature,
      uECC_secp256r1()) == 1) ? 1U : 0U;
}

uint8_t firmware_metadata_valid(const fw_metadata_t *meta)
{
  uint32_t computed_meta_crc;
  uint32_t computed_fw_crc;
  uint32_t meta_crc_offset;

  if (meta->magic != FW_META_MAGIC || meta->version != FW_META_VERSION)
  {
    return 0U;
  }

  if ((meta->flags & FW_META_FLAG_SIGNATURE_REQUIRED) == 0U)
  {
    return 0U;
  }

  if ((meta->flags & (~FW_META_FLAG_SIGNATURE_REQUIRED)) != 0U)
  {
    return 0U;
  }

  if (meta->fw_address != APPLICATION_ADDRESS)
  {
    return 0U;
  }

  if ((meta->fw_length == 0U) ||
    (meta->fw_length > APPLICATION_MAX_SIZE))
  {
    return 0U;
  }

  meta_crc_offset = (uint32_t)((const uint8_t *)&meta->meta_crc32 - (const uint8_t *)meta);
  computed_meta_crc = HAL_CRC_Calculate(&hcrc, (uint32_t *)METADATA_ADDRESS, meta_crc_offset);
  if (computed_meta_crc != meta->meta_crc32)
  {
    return 0U;
  }

  computed_fw_crc = firmware_crc32(meta->fw_address, meta->fw_length);
  if (computed_fw_crc != meta->fw_crc32)
  {
    bl_auth_cache_clear();
    return 0U;
  }

  if (firmware_trust_tag_valid(meta) == 1U)
  {
    debug_uart_tx("BL: trust tag valid\r\n");
    bl_auth_cache_store(meta->fw_crc32);
    return 1U;
  }

  /* Cached auth for unchanged firmware: keep metadata and fw CRC checks on every boot. */
  if (bl_auth_cache_match(meta->fw_crc32) == 1U)
  {
    debug_uart_tx("BL: auth cache hit\r\n");
    return 1U;
  }

  if (firmware_signature_valid(meta) == 0U)
  {
    bl_auth_cache_clear();
    return 0U;
  }

  bl_auth_cache_store(meta->fw_crc32);

  return 1U;
}

void bl_clear_boot_state_cold(const bl_reset_flags_t *reset_flags)
{
  if (reset_flags->por == 1U)
  {
    RTC->BKP1R = 0U;
    RTC->BKP2R = 0U;
    RTC->BKP3R = 0U;
    bl_auth_cache_clear();
  }
}

uint8_t bl_should_enter_dfu(const bl_reset_flags_t *reset_flags,
    uint8_t meta_valid,
    const fw_metadata_t *meta)
{
  uint8_t enter_dfu = 0U;

  if ((reset_flags->sft == 1U) && (RTC->BKP1R == BL_BKP_REQ_DFU_MAGIC))
  {
    debug_uart_tx("BL: DFU requested (BKP)\r\n");
    enter_dfu = 1U;
    RTC->BKP1R = 0U;
    RTC->BKP2R = 0U;
    RTC->BKP3R = 0U;
  }

  if (enter_dfu == 0U)
  {
    uint32_t state = RTC->BKP2R;
    uint8_t fail_count = bl_bootstate_get_failcount(state);

    if (reset_flags->iwdg == 1U)
    {
      debug_uart_tx("BL: IWDG reset\r\n");
      if ((state & BL_BKP_STATE_BOOT_IN_PROGRESS) != 0U)
      {
        if (fail_count != 0xFFU)
        {
          ++fail_count;
        }
        state = bl_bootstate_set_failcount(state, fail_count);
        RTC->BKP2R = state;
      }
    }

    if ((state & BL_BKP_STATE_FORCE_DFU) != 0U)
    {
      if ((meta_valid == 1U) && (RTC->BKP3R != 0U) && (meta->fw_crc32 != RTC->BKP3R))
      {
        debug_uart_tx("BL: new firmware detected, clearing DFU force\r\n");
        state &= ~BL_BKP_STATE_FORCE_DFU;
        state &= ~(BL_BKP_STATE_BOOT_IN_PROGRESS | BL_BKP_STATE_BOOT_OK);
        state = bl_bootstate_set_failcount(state, 0U);
        RTC->BKP2R = state;
        RTC->BKP3R = 0U;
        fail_count = 0U;
      }
      else
      {
        enter_dfu = 1U;
        debug_uart_tx("BL: DFU forced (crash loop)\r\n");
      }
    }

    if ((enter_dfu == 0U) &&
      ((state & BL_BKP_STATE_BOOT_IN_PROGRESS) != 0U) &&
      (fail_count >= (uint8_t)BL_BOOT_FAIL_THRESHOLD))
    {
      state |= BL_BKP_STATE_FORCE_DFU;
      state &= ~(BL_BKP_STATE_BOOT_IN_PROGRESS | BL_BKP_STATE_BOOT_OK);
      RTC->BKP2R = state;
      if ((RTC->BKP3R == 0U) && (meta_valid == 1U))
      {
        RTC->BKP3R = meta->fw_crc32;
      }
      enter_dfu = 1U;
      debug_uart_tx("BL: entering DFU (boot failures)\r\n");
    }
  }

  return enter_dfu;
}

void bl_mark_boot_in_progress(void)
{
  uint32_t state = RTC->BKP2R;
  state |= BL_BKP_STATE_BOOT_IN_PROGRESS;
  state &= ~BL_BKP_STATE_BOOT_OK;
  RTC->BKP2R = state;
}

void bl_clear_boot_in_progress(void)
{
  uint32_t state = RTC->BKP2R;
  state &= ~BL_BKP_STATE_BOOT_IN_PROGRESS;
  RTC->BKP2R = state;
}

void firmware_sha256(uint32_t fw_addr, uint32_t fw_len, uint8_t out[32])
{
  sha256_ctx_t ctx;

  sha256_init(&ctx);
  sha256_update(&ctx, (const uint8_t *)fw_addr, fw_len);
  sha256_final(&ctx, out);
}
