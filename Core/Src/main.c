/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file           : main.c
 * @brief          : Main program body
 ******************************************************************************
 * @attention
 *
 * Copyright (c) 2026 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usb_device.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "common.h"
#include "memory_map.h"
#include "sha256.h"
#include "uECC.h"
#include "utils.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
typedef void (*pFunction)(void);

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
/* Persistent boot state stored in RTC backup registers (STM32F072: BKP0R..BKP4R).
  This avoids relying on .noinit RAM and survives NVIC_SystemReset() and watchdog resets. */
#define BL_BKP_SIGNATURE (0x4F57424CU)     /* 'OWBL' */
#define BL_BKP_REQ_DFU_MAGIC (0x21554644U) /* 'DFU!' */

#define BL_BKP_STATE_FORCE_DFU (1U << 0U)
#define BL_BKP_STATE_BOOT_IN_PROGRESS (1U << 1U)
#define BL_BKP_STATE_BOOT_OK (1U << 2U)
#define BL_BKP_STATE_FAILCOUNT_SHIFT (8U)
#define BL_BKP_STATE_FAILCOUNT_MASK (0xFFU << BL_BKP_STATE_FAILCOUNT_SHIFT)

#define BL_BOOT_FAIL_THRESHOLD (2U)
#define BL_BKP_AUTH_CACHE_XOR (0xA5964C3DU)

#define BL_TRUST_HMAC_KEY_BYTES (32U)

/* Replace with a device-unique secret key in production provisioning. */
static const uint8_t g_bl_trust_hmac_key[BL_TRUST_HMAC_KEY_BYTES] = {
    0x3BU,
    0xA2U,
    0x6CU,
    0x91U,
    0xD4U,
    0x5EU,
    0x87U,
    0x12U,
    0x5FU,
    0xE8U,
    0x34U,
    0x9AU,
    0x21U,
    0x6DU,
    0xC3U,
    0x58U,
    0xA7U,
    0x0EU,
    0x49U,
    0xBCU,
    0x63U,
    0xF1U,
    0x2DU,
    0x80U,
    0x15U,
    0x9EU,
    0x72U,
    0x44U,
    0xD8U,
    0x0BU,
    0xC5U,
    0x6AU,
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
            0x0CU,
            0xBBU,
            0x01U,
            0xC8U,
            0x20U,
            0xE6U,
            0x2CU,
            0xAAU,
            0x76U,
            0x78U,
            0x3FU,
            0x8FU,
            0xAFU,
            0xA5U,
            0xA7U,
            0xEDU,
            0xBFU,
            0x75U,
            0xDCU,
            0x90U,
            0x44U,
            0xE0U,
            0x4AU,
            0x92U,
            0x7AU,
            0xB4U,
            0xE6U,
            0x1DU,
            0xCFU,
            0xDDU,
            0x9CU,
            0x34U,
            0x00U,
            0x0CU,
            0x9BU,
            0x5AU,
            0x54U,
            0x57U,
            0x75U,
            0xEFU,
            0xB2U,
            0xD1U,
            0x13U,
            0x23U,
            0xDEU,
            0x2EU,
            0x44U,
            0xB8U,
            0xEFU,
            0xE1U,
            0x4CU,
            0x0DU,
            0x27U,
            0xCAU,
            0xE6U,
            0xADU,
            0x72U,
            0x2BU,
            0x76U,
            0x23U,
            0x50U,
            0xB7U,
            0x95U,
            0x45U,
        },
    },
};

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
CRYP_HandleTypeDef hcryp;
__ALIGN_BEGIN static const uint8_t pKeyAES[16] __ALIGN_END = {
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                            0x00,0x00,0x00,0x00,0x00,0x00};

CRC_HandleTypeDef hcrc;

I2C_HandleTypeDef hi2c1;
I2C_HandleTypeDef hi2c2;

IWDG_HandleTypeDef hiwdg;

RTC_HandleTypeDef hrtc;

SPI_HandleTypeDef hspi1;

TIM_HandleTypeDef htim2;

UART_HandleTypeDef huart1;
UART_HandleTypeDef huart2;
UART_HandleTypeDef huart3;
DMA_HandleTypeDef hdma_usart1_tx;
DMA_HandleTypeDef hdma_usart2_rx;
DMA_HandleTypeDef hdma_usart2_tx;
DMA_HandleTypeDef hdma_usart3_rx;
DMA_HandleTypeDef hdma_usart3_tx;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_DMA_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_USART3_UART_Init(void);
static void MX_CRC_Init(void);
static void MX_I2C1_Init(void);
static void MX_I2C2_Init(void);
static void MX_RTC_Init(void);
static void MX_SPI1_Init(void);
static void MX_TIM2_Init(void);
static void MX_USART1_UART_Init(void);
static void MX_AES_Init(void);
static void MX_IWDG_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
typedef struct
{
  uint8_t por;
  uint8_t pin;
  uint8_t sft;
  uint8_t iwdg;
  uint8_t wwdg;
} bl_reset_flags_t;

static const fw_metadata_t *bl_metadata_ptr(void)
{
  return (const fw_metadata_t *)METADATA_ADDRESS;
}

static uint8_t bl_app_stack_pointer_sane(void)
{
  uint32_t app_sp = *(__IO uint32_t *)APPLICATION_ADDRESS;
  return ((app_sp & 0x2FFE0000U) == 0x20000000U) ? 1U : 0U;
}

static uint8_t bl_app_reset_vector_sane(void)
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

static bl_reset_flags_t bl_read_and_clear_reset_flags(void)
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

static void bl_leds_all_off(void)
{
  HAL_GPIO_WritePin(LD_HB_GPIO_Port, LD_HB_Pin, GPIO_PIN_SET);
}

static void bl_boot_hw_prep(void)
{
  bl_leds_all_off();
}

static void bl_prepare_usb_dfu_mode(void)
{
  bl_leds_all_off();
  HAL_GPIO_WritePin(LD_HB_GPIO_Port, LD_HB_Pin, GPIO_PIN_RESET);
}

static const uint8_t *bl_find_public_key(uint32_t key_id)
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

static void firmware_sha256(uint32_t fw_addr, uint32_t fw_len, uint8_t out[32])
{
  sha256_ctx_t ctx;

  sha256_init(&ctx);
  sha256_update(&ctx, (const uint8_t *)fw_addr, fw_len);
  sha256_final(&ctx, out);
}

static void bl_bkp_enable(void)
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

static void bl_bootstate_init(void)
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

static uint8_t bl_bootstate_get_failcount(uint32_t state)
{
  return (uint8_t)((state & BL_BKP_STATE_FAILCOUNT_MASK) >> BL_BKP_STATE_FAILCOUNT_SHIFT);
}

static uint8_t bl_auth_cache_match(uint32_t fw_crc32)
{
  uint32_t cache = RTC->BKP4R;

  if (cache == 0U)
  {
    return 0U;
  }

  return (((cache ^ BL_BKP_AUTH_CACHE_XOR) == fw_crc32) ? 1U : 0U);
}

static void bl_auth_cache_store(uint32_t fw_crc32)
{
  RTC->BKP4R = fw_crc32 ^ BL_BKP_AUTH_CACHE_XOR;
}

static void bl_auth_cache_clear(void)
{
  RTC->BKP4R = 0U;
}

static uint32_t bl_bootstate_set_failcount(uint32_t state, uint8_t count)
{
  uint32_t s = state & ~BL_BKP_STATE_FAILCOUNT_MASK;
  s |= ((uint32_t)count << BL_BKP_STATE_FAILCOUNT_SHIFT) & BL_BKP_STATE_FAILCOUNT_MASK;
  return s;
}

static void debug_uart_tx(const char *msg)
{
  uint32_t guard;
  uint32_t idx = 0U;

  while ((msg[idx] != '\0') && (idx < 255U))
  {
    guard = 1000000U;
    while (((huart1.Instance->ISR & USART_ISR_TXE) == 0U) && (guard > 0U))
    {
      --guard;
    }

    if (guard == 0U)
    {
      return;
    }

    huart1.Instance->TDR = (uint8_t)msg[idx];
    ++idx;
  }

  guard = 1000000U;
  while (((huart1.Instance->ISR & USART_ISR_TC) == 0U) && (guard > 0U))
  {
    --guard;
  }
}

static void debug_uart_clear(void)
{
  (void)HAL_UART_Transmit(&huart1, (uint8_t *)"\033c", 2U, 100U);
}

static void jump_to_application(uint32_t app_base)
{
    pFunction jump_to_app;
    uint32_t jump_address;
    const uint32_t *app_vectors = (const uint32_t *)app_base;

    debug_uart_tx("BL: jump prep\r\n");

    __disable_irq();

    /* Stop SysTick */
    SysTick->CTRL = 0;
    SysTick->LOAD = 0;
    SysTick->VAL  = 0;

  /* Reset clock configuration to default (HSI) */
  HAL_RCC_DeInit();

  /* Disable all NVIC interrupts */
  for (uint32_t i = 0; i < 8; i++)
  {
      NVIC->ICER[i] = 0xFFFFFFFF;
      NVIC->ICPR[i] = 0xFFFFFFFF;
  }

  /* Set vector table location */
  SCB->VTOR = app_base;

  /* Load MSP from application's vector table */
  __set_MSP(app_vectors[0]);

  /* Jump to application's Reset_Handler */
  jump_address = app_vectors[1];
  jump_to_app = (pFunction)jump_address;

  __enable_irq();

  debug_uart_tx("BL: jump\r\n");

  jump_to_app();

  while (1)
  {
  }
}

/**
 * @brief  Compute CRC32 over firmware bytes using STM32 CRC peripheral.
 */
static uint32_t firmware_crc32(uint32_t fw_addr, uint32_t fw_len)
{
  return HAL_CRC_Calculate(&hcrc, (uint32_t *)fw_addr, fw_len);
}

static uint8_t bl_consttime_equal(const uint8_t *a, const uint8_t *b, uint32_t len)
{
  uint8_t diff = 0U;
  uint32_t i;

  for (i = 0U; i < len; ++i)
  {
    diff |= (uint8_t)(a[i] ^ b[i]);
  }

  return (diff == 0U) ? 1U : 0U;
}

static void bl_hmac_sha256(const uint8_t *key,
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

static uint8_t firmware_trust_tag_valid(const fw_metadata_t *meta)
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

/**
 * @brief  Verify firmware signature using key selected by metadata key_id.
 */
static uint8_t firmware_signature_valid(const fw_metadata_t *meta)
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
                      uECC_secp256r1()) == 1)
             ? 1U
             : 0U;
}

/**
 * @brief  Validate metadata page and firmware authenticity.
 * @retval 1 if valid and authenticated, 0 otherwise
 */
static uint8_t firmware_metadata_valid(const fw_metadata_t *meta)
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

static void bl_clear_boot_state_cold(const bl_reset_flags_t *reset_flags)
{
  if (reset_flags->por == 1U)
  {
    RTC->BKP1R = 0U;
    RTC->BKP2R = 0U;
    RTC->BKP3R = 0U;
    bl_auth_cache_clear();
  }
}

static uint8_t bl_should_enter_dfu(const bl_reset_flags_t *reset_flags,
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

static void bl_mark_boot_in_progress(void)
{
  uint32_t state = RTC->BKP2R;
  state |= BL_BKP_STATE_BOOT_IN_PROGRESS;
  state &= ~BL_BKP_STATE_BOOT_OK;
  RTC->BKP2R = state;
}

static void bl_clear_boot_in_progress(void)
{
  uint32_t state = RTC->BKP2R;
  state &= ~BL_BKP_STATE_BOOT_IN_PROGRESS;
  RTC->BKP2R = state;
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_DMA_Init();
  MX_USART2_UART_Init();
  MX_USART3_UART_Init();
  MX_CRC_Init();
  MX_I2C1_Init();
  MX_I2C2_Init();
  MX_RTC_Init();
  MX_SPI1_Init();
  MX_TIM2_Init();
  MX_USART1_UART_Init();
  MX_AES_Init();
  /* USER CODE BEGIN 2 */
  const fw_metadata_t *meta = bl_metadata_ptr();
  bl_reset_flags_t reset_flags;
  uint8_t app_sp_sane;
  uint8_t app_rv_sane;
  uint8_t meta_valid;
  uint8_t enter_dfu;

  bl_boot_hw_prep();

  debug_uart_clear();
  debug_uart_tx("LIFU Transmitter Bootloader\r\n");
  debug_uart_tx("VER: ");
  debug_uart_tx(FW_VERSION_STRING);
  debug_uart_tx(" (");
  debug_uart_tx(FW_SHA_STRING);
  debug_uart_tx(")\r\nDate: ");
  debug_uart_tx(FW_BUILD_TIME_STRING);
  debug_uart_tx("\r\n");

  debug_uart_tx("BL: boot start\r\n");

  reset_flags = bl_read_and_clear_reset_flags();
  debug_uart_tx("BL: bootstate init\r\n");
  bl_bootstate_init();
  bl_clear_boot_state_cold(&reset_flags);

  debug_uart_tx("BL: app_sp_sane check\r\n");
  app_sp_sane = bl_app_stack_pointer_sane();
  debug_uart_tx("BL: app_rv_sane check\r\n");
  app_rv_sane = bl_app_reset_vector_sane();
  if ((app_sp_sane == 1U) && (app_rv_sane == 1U))
  {
    debug_uart_tx("BL: metadata/auth check\r\n");
    meta_valid = firmware_metadata_valid(meta);
  }
  else
  {
    debug_uart_tx("BL: metadata/auth skipped\r\n");
    meta_valid = 0U;
  }
  enter_dfu = bl_should_enter_dfu(&reset_flags, meta_valid, meta);

  if (app_sp_sane == 0U)
  {
    debug_uart_tx("BL: app SP invalid\r\n");
  }

  if (app_rv_sane == 0U)
  {
    debug_uart_tx("BL: app RV invalid\r\n");
  }

  if (meta_valid == 0U)
  {
    debug_uart_tx("BL: metadata/auth invalid\r\n");
  }

  /* Boot only if metadata/authentication checks pass and app stack pointer is sane. */
  if ((enter_dfu == 0U) && (app_sp_sane == 1U) && (app_rv_sane == 1U) && (meta_valid == 1U))
  {
    bl_mark_boot_in_progress();

    /* Start watchdog before handing off so a hung app will reset back into the bootloader. */
    MX_IWDG_Init();

    debug_uart_tx("BL: jumping to app\r\n");
    jump_to_application(APPLICATION_ADDRESS);
  }

  debug_uart_tx("BL: entering DFU mode\r\n");

  bl_clear_boot_in_progress();
  bl_prepare_usb_dfu_mode();
  
  debug_uart_tx("BL: init USB\r\n");
  MX_USB_DEVICE_Init();
  HAL_Delay(100);
  debug_uart_tx("BL: USB ready\r\n");
    
  MX_IWDG_Init();
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
    HAL_Delay(250);
    /* Refresh IWDG: reload counter */
    if(HAL_IWDG_Refresh(&hiwdg) != HAL_OK)
    {
      /* Refresh Error */
      Error_Handler();
    }
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI48|RCC_OSCILLATORTYPE_LSI
                              |RCC_OSCILLATORTYPE_HSE|RCC_OSCILLATORTYPE_MSI;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.HSI48State = RCC_HSI48_ON;
  RCC_OscInitStruct.LSIState = RCC_LSI_ON;
  RCC_OscInitStruct.MSIState = RCC_MSI_ON;
  RCC_OscInitStruct.MSICalibrationValue = 0;
  RCC_OscInitStruct.MSIClockRange = RCC_MSIRANGE_6;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 2;
  RCC_OscInitStruct.PLL.PLLN = 16;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV7;
  RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV4;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV4;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
  HAL_RCC_MCOConfig(RCC_MCO1, RCC_MCO1SOURCE_MSI, RCC_MCODIV_2);
}

/**
  * @brief AES Initialization Function
  * @param None
  * @retval None
  */
static void MX_AES_Init(void)
{

  /* USER CODE BEGIN AES_Init 0 */

  /* USER CODE END AES_Init 0 */

  /* USER CODE BEGIN AES_Init 1 */

  /* USER CODE END AES_Init 1 */
  hcryp.Instance = AES;
  hcryp.Init.DataType = CRYP_DATATYPE_32B;
  hcryp.Init.KeySize = CRYP_KEYSIZE_128B;
  hcryp.Init.OperatingMode = CRYP_ALGOMODE_ENCRYPT;
  hcryp.Init.ChainingMode = CRYP_CHAINMODE_AES_ECB;
  hcryp.Init.KeyWriteFlag = CRYP_KEY_WRITE_ENABLE;
  hcryp.Init.pKey = (uint8_t *)pKeyAES;
  if (HAL_CRYP_Init(&hcryp) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN AES_Init 2 */

  /* USER CODE END AES_Init 2 */

}

/**
  * @brief CRC Initialization Function
  * @param None
  * @retval None
  */
static void MX_CRC_Init(void)
{

  /* USER CODE BEGIN CRC_Init 0 */

  /* USER CODE END CRC_Init 0 */

  /* USER CODE BEGIN CRC_Init 1 */

  /* USER CODE END CRC_Init 1 */
  hcrc.Instance = CRC;
  hcrc.Init.DefaultPolynomialUse = DEFAULT_POLYNOMIAL_ENABLE;
  hcrc.Init.DefaultInitValueUse = DEFAULT_INIT_VALUE_ENABLE;
  hcrc.Init.InputDataInversionMode = CRC_INPUTDATA_INVERSION_NONE;
  hcrc.Init.OutputDataInversionMode = CRC_OUTPUTDATA_INVERSION_DISABLE;
  hcrc.InputDataFormat = CRC_INPUTDATA_FORMAT_BYTES;
  if (HAL_CRC_Init(&hcrc) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN CRC_Init 2 */

  /* USER CODE END CRC_Init 2 */

}

/**
  * @brief I2C1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_I2C1_Init(void)
{

  /* USER CODE BEGIN I2C1_Init 0 */

  /* USER CODE END I2C1_Init 0 */

  /* USER CODE BEGIN I2C1_Init 1 */

  /* USER CODE END I2C1_Init 1 */
  hi2c1.Instance = I2C1;
  hi2c1.Init.Timing = 0x10805D88;
  hi2c1.Init.OwnAddress1 = 0;
  hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
  hi2c1.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
  hi2c1.Init.OwnAddress2 = 0;
  hi2c1.Init.OwnAddress2Masks = I2C_OA2_NOMASK;
  hi2c1.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
  hi2c1.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
  if (HAL_I2C_Init(&hi2c1) != HAL_OK)
  {
    Error_Handler();
  }

  /** Configure Analogue filter
  */
  if (HAL_I2CEx_ConfigAnalogFilter(&hi2c1, I2C_ANALOGFILTER_ENABLE) != HAL_OK)
  {
    Error_Handler();
  }

  /** Configure Digital filter
  */
  if (HAL_I2CEx_ConfigDigitalFilter(&hi2c1, 0) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN I2C1_Init 2 */

  /* USER CODE END I2C1_Init 2 */

}

/**
  * @brief I2C2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_I2C2_Init(void)
{

  /* USER CODE BEGIN I2C2_Init 0 */

  /* USER CODE END I2C2_Init 0 */

  /* USER CODE BEGIN I2C2_Init 1 */

  /* USER CODE END I2C2_Init 1 */
  hi2c2.Instance = I2C2;
  hi2c2.Init.Timing = 0x10805D88;
  hi2c2.Init.OwnAddress1 = 0;
  hi2c2.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
  hi2c2.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
  hi2c2.Init.OwnAddress2 = 0;
  hi2c2.Init.OwnAddress2Masks = I2C_OA2_NOMASK;
  hi2c2.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
  hi2c2.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
  if (HAL_I2C_Init(&hi2c2) != HAL_OK)
  {
    Error_Handler();
  }

  /** Configure Analogue filter
  */
  if (HAL_I2CEx_ConfigAnalogFilter(&hi2c2, I2C_ANALOGFILTER_ENABLE) != HAL_OK)
  {
    Error_Handler();
  }

  /** Configure Digital filter
  */
  if (HAL_I2CEx_ConfigDigitalFilter(&hi2c2, 0) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN I2C2_Init 2 */

  /* USER CODE END I2C2_Init 2 */

}

/**
  * @brief IWDG Initialization Function
  * @param None
  * @retval None
  */
static void MX_IWDG_Init(void)
{

  /* USER CODE BEGIN IWDG_Init 0 */

  /* USER CODE END IWDG_Init 0 */

  /* USER CODE BEGIN IWDG_Init 1 */

  /* USER CODE END IWDG_Init 1 */
  hiwdg.Instance = IWDG;
  hiwdg.Init.Prescaler = IWDG_PRESCALER_16;
  hiwdg.Init.Window = 4095;
  hiwdg.Init.Reload = 4095;
  if (HAL_IWDG_Init(&hiwdg) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN IWDG_Init 2 */

  /* USER CODE END IWDG_Init 2 */

}

/**
  * @brief RTC Initialization Function
  * @param None
  * @retval None
  */
static void MX_RTC_Init(void)
{

  /* USER CODE BEGIN RTC_Init 0 */

  /* USER CODE END RTC_Init 0 */

  /* USER CODE BEGIN RTC_Init 1 */

  /* USER CODE END RTC_Init 1 */

  /** Initialize RTC Only
  */
  hrtc.Instance = RTC;
  hrtc.Init.HourFormat = RTC_HOURFORMAT_24;
  hrtc.Init.AsynchPrediv = 127;
  hrtc.Init.SynchPrediv = 255;
  hrtc.Init.OutPut = RTC_OUTPUT_DISABLE;
  hrtc.Init.OutPutRemap = RTC_OUTPUT_REMAP_NONE;
  hrtc.Init.OutPutPolarity = RTC_OUTPUT_POLARITY_HIGH;
  hrtc.Init.OutPutType = RTC_OUTPUT_TYPE_OPENDRAIN;
  if (HAL_RTC_Init(&hrtc) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RTC_Init 2 */

  /* USER CODE END RTC_Init 2 */

}

/**
  * @brief SPI1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_SPI1_Init(void)
{

  /* USER CODE BEGIN SPI1_Init 0 */

  /* USER CODE END SPI1_Init 0 */

  /* USER CODE BEGIN SPI1_Init 1 */

  /* USER CODE END SPI1_Init 1 */
  /* SPI1 parameter configuration*/
  hspi1.Instance = SPI1;
  hspi1.Init.Mode = SPI_MODE_MASTER;
  hspi1.Init.Direction = SPI_DIRECTION_2LINES;
  hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi1.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi1.Init.NSS = SPI_NSS_SOFT;
  hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_64;
  hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi1.Init.CRCPolynomial = 7;
  hspi1.Init.CRCLength = SPI_CRC_LENGTH_DATASIZE;
  hspi1.Init.NSSPMode = SPI_NSS_PULSE_ENABLE;
  if (HAL_SPI_Init(&hspi1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN SPI1_Init 2 */

  /* USER CODE END SPI1_Init 2 */

}

/**
  * @brief TIM2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_TIM2_Init(void)
{

  /* USER CODE BEGIN TIM2_Init 0 */

  /* USER CODE END TIM2_Init 0 */

  TIM_ClockConfigTypeDef sClockSourceConfig = {0};
  TIM_MasterConfigTypeDef sMasterConfig = {0};

  /* USER CODE BEGIN TIM2_Init 1 */

  /* USER CODE END TIM2_Init 1 */
  htim2.Instance = TIM2;
  htim2.Init.Prescaler = 48-1;
  htim2.Init.CounterMode = TIM_COUNTERMODE_UP;
  htim2.Init.Period = 4294967295;
  htim2.Init.ClockDivision = TIM_CLOCKDIVISION_DIV1;
  htim2.Init.AutoReloadPreload = TIM_AUTORELOAD_PRELOAD_DISABLE;
  if (HAL_TIM_Base_Init(&htim2) != HAL_OK)
  {
    Error_Handler();
  }
  sClockSourceConfig.ClockSource = TIM_CLOCKSOURCE_INTERNAL;
  if (HAL_TIM_ConfigClockSource(&htim2, &sClockSourceConfig) != HAL_OK)
  {
    Error_Handler();
  }
  sMasterConfig.MasterOutputTrigger = TIM_TRGO_RESET;
  sMasterConfig.MasterSlaveMode = TIM_MASTERSLAVEMODE_DISABLE;
  if (HAL_TIMEx_MasterConfigSynchronization(&htim2, &sMasterConfig) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN TIM2_Init 2 */

  /* USER CODE END TIM2_Init 2 */

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  huart2.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart2.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_HalfDuplex_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief USART3 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART3_UART_Init(void)
{

  /* USER CODE BEGIN USART3_Init 0 */

  /* USER CODE END USART3_Init 0 */

  /* USER CODE BEGIN USART3_Init 1 */

  /* USER CODE END USART3_Init 1 */
  huart3.Instance = USART3;
  huart3.Init.BaudRate = 115200;
  huart3.Init.WordLength = UART_WORDLENGTH_8B;
  huart3.Init.StopBits = UART_STOPBITS_1;
  huart3.Init.Parity = UART_PARITY_NONE;
  huart3.Init.Mode = UART_MODE_TX_RX;
  huart3.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart3.Init.OverSampling = UART_OVERSAMPLING_16;
  huart3.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart3.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_HalfDuplex_Init(&huart3) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART3_Init 2 */

  /* USER CODE END USART3_Init 2 */

}

/**
  * Enable DMA controller clock
  */
static void MX_DMA_Init(void)
{

  /* DMA controller clock enable */
  __HAL_RCC_DMA1_CLK_ENABLE();

  /* DMA interrupt init */
  /* DMA1_Channel2_IRQn interrupt configuration */
  HAL_NVIC_SetPriority(DMA1_Channel2_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(DMA1_Channel2_IRQn);
  /* DMA1_Channel3_IRQn interrupt configuration */
  HAL_NVIC_SetPriority(DMA1_Channel3_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(DMA1_Channel3_IRQn);
  /* DMA1_Channel4_IRQn interrupt configuration */
  HAL_NVIC_SetPriority(DMA1_Channel4_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(DMA1_Channel4_IRQn);
  /* DMA1_Channel6_IRQn interrupt configuration */
  HAL_NVIC_SetPriority(DMA1_Channel6_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(DMA1_Channel6_IRQn);
  /* DMA1_Channel7_IRQn interrupt configuration */
  HAL_NVIC_SetPriority(DMA1_Channel7_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(DMA1_Channel7_IRQn);

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOB, TR1_EN_Pin|REFSEL_Pin|TR3_EN_Pin|HW_SW_CTRL_Pin
                          |TR2_EN_Pin|TR7_EN_Pin|TR6_EN_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOA, TX1_CS_Pin|TX2_CS_Pin|TR8_EN_Pin|TX_STDBY_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOC, TR4_EN_Pin|LD_HB_Pin|TX_RESET_L_Pin|TX_CW_EN_Pin
                          |TR5_EN_Pin|RDY_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(SYSTEM_RDY_GPIO_Port, SYSTEM_RDY_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : INT_Pin */
  GPIO_InitStruct.Pin = INT_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(INT_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pins : GPIO_1_Pin TX1_SHUTZ_Pin RX_I2C_SDA_Pin PC1
                           RX_I2C_SCL_Pin RX_RDY_Pin PC3 */
  GPIO_InitStruct.Pin = GPIO_1_Pin|TX1_SHUTZ_Pin|RX_I2C_SDA_Pin|GPIO_PIN_1
                          |RX_I2C_SCL_Pin|RX_RDY_Pin|GPIO_PIN_3;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

  /*Configure GPIO pins : TR1_EN_Pin REFSEL_Pin TR3_EN_Pin HW_SW_CTRL_Pin
                           TR2_EN_Pin TR7_EN_Pin TR6_EN_Pin */
  GPIO_InitStruct.Pin = TR1_EN_Pin|REFSEL_Pin|TR3_EN_Pin|HW_SW_CTRL_Pin
                          |TR2_EN_Pin|TR7_EN_Pin|TR6_EN_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /*Configure GPIO pins : PDN_Pin EXT_Pin */
  GPIO_InitStruct.Pin = PDN_Pin|EXT_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /*Configure GPIO pins : TX1_CS_Pin TX2_CS_Pin TR8_EN_Pin TX_STDBY_Pin */
  GPIO_InitStruct.Pin = TX1_CS_Pin|TX2_CS_Pin|TR8_EN_Pin|TX_STDBY_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  /*Configure GPIO pins : TR4_EN_Pin LD_HB_Pin TX_RESET_L_Pin TX_CW_EN_Pin
                           TR5_EN_Pin RDY_Pin */
  GPIO_InitStruct.Pin = TR4_EN_Pin|LD_HB_Pin|TX_RESET_L_Pin|TX_CW_EN_Pin
                          |TR5_EN_Pin|RDY_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

  /*Configure GPIO pin : SYSTEM_RDY_Pin */
  GPIO_InitStruct.Pin = SYSTEM_RDY_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(SYSTEM_RDY_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : REF_CLK_Pin */
  GPIO_InitStruct.Pin = REF_CLK_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  GPIO_InitStruct.Alternate = GPIO_AF0_MCO;
  HAL_GPIO_Init(REF_CLK_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pins : TX2_SHUTZ_Pin POWER_GOOD_Pin */
  GPIO_InitStruct.Pin = TX2_SHUTZ_Pin|POWER_GOOD_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /*Configure GPIO pin : TRIGGER_Pin */
  GPIO_InitStruct.Pin = TRIGGER_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
  GPIO_InitStruct.Alternate = GPIO_AF14_TIM15;
  HAL_GPIO_Init(TRIGGER_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : RST_Pin */
  GPIO_InitStruct.Pin = RST_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(RST_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  Period elapsed callback in non blocking mode
  * @note   This function is called  when TIM6 interrupt took place, inside
  * HAL_TIM_IRQHandler(). It makes a direct call to HAL_IncTick() to increment
  * a global variable "uwTick" used as application time base.
  * @param  htim : TIM handle
  * @retval None
  */
void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
{
  /* USER CODE BEGIN Callback 0 */

  /* USER CODE END Callback 0 */
  if (htim->Instance == TIM6)
  {
    HAL_IncTick();
  }
  /* USER CODE BEGIN Callback 1 */

  /* USER CODE END Callback 1 */
}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
