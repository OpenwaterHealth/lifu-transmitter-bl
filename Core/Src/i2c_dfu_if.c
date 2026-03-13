/*
 * i2c_dfu_if.c
 *
 * I2C slave DFU interface — allows a downstream transmitter (not connected to
 * USB) to receive firmware updates relayed over I2C from the upstream
 * transmitter.  See i2c_dfu_if.h for the full protocol description.
 *
 * Implementation notes
 * --------------------
 * HAL I2C "listen" mode is used so the peripheral remains in slave mode
 * continuously:
 *
 *   HAL_I2C_EnableListen_IT()
 *       ↓  (master starts a transaction)
 *   HAL_I2C_AddrCallback()           ← direction: RECEIVE or TRANSMIT
 *       ↓
 *   HAL_I2C_Slave_Sequential_Receive_IT()  or  _Transmit_IT()
 *       ↓  (STOP detected)
 *   HAL_I2C_ListenCpltCallback()     ← re-arms listen, sets cmd-pending flag
 *
 * Flash erase/program operations are executed in I2C_DFU_Process() (called
 * from the main loop) rather than inside ISR callbacks to keep ISR latency
 * low and to allow IWDG refresh during long full-erase sequences.
 */

#include "i2c_dfu_if.h"
#include "common.h"
#include "memory_map.h"
#include <string.h>

/* -------------------------------------------------------------------------
 * Internal sizing / layout
 * ---------------------------------------------------------------------- */

/* Byte offsets within a write transaction buffer */
#define CMD_OFFSET    0U   /* 1 byte: command */
#define ADDR_OFFSET   1U   /* 4 bytes: target flash address (LE) */
#define LEN_OFFSET    5U   /* 2 bytes: data length (LE) */
#define DATA_OFFSET   7U   /* N bytes: firmware payload */

#define HDR_SIZE      7U   /* CMD + ADDR + LEN */

/* Receive buffer: header + maximum firmware payload */
#define RX_BUF_SIZE   (HDR_SIZE + I2C_DFU_MAX_XFER_SIZE)

/* Writable flash regions (mirrors usbd_dfu_if.c) */
#define DFU_META_START   METADATA_ADDRESS
#define DFU_META_END     (METADATA_ADDRESS + FLASH_PAGE_SIZE)
#define DFU_APP_START    APPLICATION_ADDRESS
#define DFU_APP_SIZE     APPLICATION_MAX_SIZE
#define DFU_APP_END      (DFU_APP_START + DFU_APP_SIZE)
#define ERASE_ALL_ADDR   0xFFFFFFFFU

/* -------------------------------------------------------------------------
 * Module state
 * ---------------------------------------------------------------------- */

typedef enum
{
    MOD_IDLE = 0,   /* Listening, no pending work       */
    MOD_CMD_READY,  /* A complete packet has been rxd   */
    MOD_BUSY,       /* Flash operation in progress      */
    MOD_RESET,      /* Waiting to call NVIC_SystemReset */
} mod_state_t;

static volatile mod_state_t  g_mod_state  = MOD_IDLE;
static volatile int           g_rx_step   = 0;  /* 0 = awaiting header, 1 = awaiting DNLOAD data */

/* DFU-level state (reported in every read response) */
static uint8_t  g_dfu_state  = I2C_DFU_STATE_IDLE;
static uint8_t  g_last_status = I2C_DFU_STATUS_OK;

/* Receive buffer — filled by ISR for flash commands, consumed by I2C_DFU_Process() */
static uint8_t   g_rx_buf[RX_BUF_SIZE];
static uint16_t  g_rx_len = 0U;  /* actual bytes received in last write txn */

/* Separate single-byte buffer for inline (non-flash) command receives.
 * Using a dedicated buffer ensures that a GETSTATUS/GETVERSION/etc. arriving
 * while an ERASE or DNLOAD is queued never overwrites g_rx_buf[CMD_OFFSET]
 * or zeroes g_rx_len, which would corrupt the pending flash command. */
static uint8_t   g_inline_cmd = 0U;

/* Transmit buffer — populated by process_command(), sent by ISR.
 * Sized to hold the largest possible response: the GETVERSION payload
 * is [status:1][state:1][version:I2C_DFU_VERSION_STR_MAX]. */
#define TX_BUF_SIZE  (2U + I2C_DFU_VERSION_STR_MAX)
static uint8_t   g_tx_buf[TX_BUF_SIZE];
static uint16_t  g_tx_len = 2U;

/* Extern handles defined in main.c */
extern IWDG_HandleTypeDef hiwdg;

/* -------------------------------------------------------------------------
 * Private helpers
 * ---------------------------------------------------------------------- */

static uint32_t get_page(uint32_t addr)
{
    if (addr < (FLASH_BASE + FLASH_BANK_SIZE))
    {
        return (addr - FLASH_BASE) / FLASH_PAGE_SIZE;
    }
    return (addr - (FLASH_BASE + FLASH_BANK_SIZE)) / FLASH_PAGE_SIZE;
}

static uint8_t is_writable(uint32_t addr)
{
    if ((addr >= DFU_META_START) && (addr < DFU_META_END)) { return 1U; }
    if ((addr >= DFU_APP_START)  && (addr < DFU_APP_END))  { return 1U; }
    return 0U;
}

static uint8_t do_erase(uint32_t addr)
{
    FLASH_EraseInitTypeDef erase = {0};
    uint32_t page_error = 0U;

    erase.TypeErase = FLASH_TYPEERASE_PAGES;
    erase.NbPages   = 1U;
    erase.Banks     = FLASH_BANK_1;

    __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_WRPERR | FLASH_FLAG_PROGERR);

    if (addr == ERASE_ALL_ADDR)
    {
        for (uint32_t a = DFU_APP_START; a < DFU_APP_END; a += FLASH_PAGE_SIZE)
        {
            erase.Page = get_page(a);
            if (HAL_FLASHEx_Erase(&erase, &page_error) != HAL_OK)
            {
                return I2C_DFU_STATUS_FLASH_ERR;
            }
            /* Refresh watchdog during the potentially long full-erase loop */
            HAL_IWDG_Refresh(&hiwdg);
        }
        return I2C_DFU_STATUS_OK;
    }

    uint32_t page_addr = addr & ~((uint32_t)(FLASH_PAGE_SIZE - 1U));
    if (is_writable(page_addr) == 0U)
    {
        return I2C_DFU_STATUS_BAD_ADDR;
    }

    erase.Page = get_page(page_addr);
    if (HAL_FLASHEx_Erase(&erase, &page_error) != HAL_OK)
    {
        return I2C_DFU_STATUS_FLASH_ERR;
    }
    return I2C_DFU_STATUS_OK;
}

static uint8_t do_write(uint8_t *src, uint32_t dest, uint32_t len)
{
    if (((dest & 7U) != 0U) || (len == 0U))
    {
        return I2C_DFU_STATUS_BAD_ADDR;
    }
    if ((is_writable(dest) == 0U) || (is_writable(dest + len - 1U) == 0U))
    {
        return I2C_DFU_STATUS_BAD_ADDR;
    }

    __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_WRPERR | FLASH_FLAG_PROGERR);

    for (uint32_t i = 0U; i < len; i += 8U)
    {
        uint64_t dw = 0xFFFFFFFFFFFFFFFFULL;
        uint32_t tail = (len - i >= 8U) ? 8U : (len - i);

        for (uint32_t j = 0U; j < tail; j++)
        {
            ((uint8_t *)&dw)[j] = src[i + j];
        }

        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, dest + i, dw) != HAL_OK)
        {
            return I2C_DFU_STATUS_FLASH_ERR;
        }
        if (*(volatile uint64_t *)(dest + i) != dw)
        {
            return I2C_DFU_STATUS_FLASH_ERR;
        }
    }
    return I2C_DFU_STATUS_OK;
}

static void set_response(uint8_t status)
{
    g_last_status = status;
    g_tx_buf[0]   = status;
    g_tx_buf[1]   = g_dfu_state;
    g_tx_len      = 2U;
}

static void process_command(void)
{
    if (g_rx_len < 1U)
    {
        set_response(I2C_DFU_STATUS_ERROR);
        g_mod_state = MOD_IDLE;
        return;
    }

    uint8_t cmd    = g_rx_buf[CMD_OFFSET];
    uint8_t result = I2C_DFU_STATUS_OK;

    switch (cmd)
    {
        /* ---- ERASE --------------------------------------------------- */
        case I2C_DFU_CMD_ERASE:
        {
            if (g_rx_len < (ADDR_OFFSET + 4U))
            {
                result = I2C_DFU_STATUS_ERROR;
                break;
            }
            uint32_t addr;
            memcpy(&addr, &g_rx_buf[ADDR_OFFSET], sizeof(addr));

            g_dfu_state = I2C_DFU_STATE_DNBUSY;
            HAL_FLASH_Unlock();
            result = do_erase(addr);
            HAL_FLASH_Lock();
            g_dfu_state = (result == I2C_DFU_STATUS_OK)
                          ? I2C_DFU_STATE_DNLOAD_IDLE
                          : I2C_DFU_STATE_ERROR;
            break;
        }

        /* ---- DNLOAD -------------------------------------------------- */
        case I2C_DFU_CMD_DNLOAD:
        {
            if (g_rx_len < (DATA_OFFSET + 1U))
            {
                result = I2C_DFU_STATUS_ERROR;
                break;
            }
            uint32_t addr;
            uint16_t len;
            memcpy(&addr, &g_rx_buf[ADDR_OFFSET], sizeof(addr));
            memcpy(&len,  &g_rx_buf[LEN_OFFSET],  sizeof(len));

            if (((uint32_t)DATA_OFFSET + (uint32_t)len) > (uint32_t)g_rx_len)
            {
                result = I2C_DFU_STATUS_ERROR;
                break;
            }

            g_dfu_state = I2C_DFU_STATE_DNBUSY;
            HAL_FLASH_Unlock();
            result = do_write(&g_rx_buf[DATA_OFFSET], addr, (uint32_t)len);
            HAL_FLASH_Lock();
            g_dfu_state = (result == I2C_DFU_STATUS_OK)
                          ? I2C_DFU_STATE_DNLOAD_IDLE
                          : I2C_DFU_STATE_ERROR;
            break;
        }

        /* ---- GETSTATUS ----------------------------------------------- */
        case I2C_DFU_CMD_GETSTATUS:
        {
            /* Response is built by set_response() below using g_last_status */
            result = g_last_status;
            break;
        }

        /* ---- MANIFEST ------------------------------------------------ */
        case I2C_DFU_CMD_MANIFEST:
        {
            g_dfu_state = I2C_DFU_STATE_MANIFEST;
            HAL_FLASH_Lock();
            g_dfu_state = I2C_DFU_STATE_IDLE;
            result = I2C_DFU_STATUS_OK;
            break;
        }

        /* ---- RESET --------------------------------------------------- */
        case I2C_DFU_CMD_RESET:
        {
            set_response(I2C_DFU_STATUS_OK);
            g_mod_state = MOD_RESET;
            return;  /* early return — reset issued in I2C_DFU_Process() */
        }

        /* ---- GETVERSION ---------------------------------------------- */
        case I2C_DFU_CMD_GETVERSION:
        {
            const char *ver = FW_VERSION_STRING;
            size_t ver_len = strlen(ver);
            if (ver_len > (size_t)I2C_DFU_VERSION_STR_MAX)
            {
                ver_len = (size_t)I2C_DFU_VERSION_STR_MAX;
            }
            g_tx_buf[0]   = I2C_DFU_STATUS_OK;
            g_tx_buf[1]   = g_dfu_state;
            memset(&g_tx_buf[2], 0, (size_t)I2C_DFU_VERSION_STR_MAX);
            memcpy(&g_tx_buf[2], ver, ver_len);
            g_tx_len      = (uint16_t)(2U + (uint16_t)I2C_DFU_VERSION_STR_MAX);
            g_last_status = I2C_DFU_STATUS_OK;
            g_rx_len      = 0U;
            g_mod_state   = MOD_IDLE;
            return;  /* early return — tx_buf already fully populated */
        }

        default:
        {
            result = I2C_DFU_STATUS_ERROR;
            break;
        }
    }

    set_response(result);
    g_rx_len    = 0U;
    g_mod_state = MOD_IDLE;
}

/* -------------------------------------------------------------------------
 * Inline handler — called from ISR for commands that need NO flash ops.
 *
 * These commands (GETSTATUS, GETVERSION, MANIFEST, RESET) are processed
 * immediately when the command byte is received so that g_tx_buf is fully
 * populated before the master ever issues its read transaction.  This avoids
 * any dependency on the main-loop calling I2C_DFU_Process() in time.
 * ---------------------------------------------------------------------- */

static void process_inline(uint8_t cmd)
{

    switch (cmd)
    {
        case I2C_DFU_CMD_GETSTATUS:
        {
            g_tx_buf[0] = g_last_status;
            g_tx_buf[1] = g_dfu_state;
            g_tx_len    = 2U;
            break;
        }

        case I2C_DFU_CMD_GETVERSION:
        {
            const char *ver = FW_VERSION_STRING;
            size_t ver_len  = strlen(ver);
            if (ver_len > (size_t)I2C_DFU_VERSION_STR_MAX)
            {
                ver_len = (size_t)I2C_DFU_VERSION_STR_MAX;
            }
            g_tx_buf[0]   = I2C_DFU_STATUS_OK;
            g_tx_buf[1]   = g_dfu_state;
            memset(&g_tx_buf[2], 0, (size_t)I2C_DFU_VERSION_STR_MAX);
            memcpy(&g_tx_buf[2], ver, ver_len);
            g_tx_len      = (uint16_t)(2U + (uint16_t)I2C_DFU_VERSION_STR_MAX);
            g_last_status = I2C_DFU_STATUS_OK;
            break;
        }

        case I2C_DFU_CMD_MANIFEST:
        {
            HAL_FLASH_Lock();
            g_dfu_state   = I2C_DFU_STATE_IDLE;
            g_last_status = I2C_DFU_STATUS_OK;
            g_tx_buf[0]   = I2C_DFU_STATUS_OK;
            g_tx_buf[1]   = I2C_DFU_STATE_IDLE;
            g_tx_len      = 2U;
            g_rx_len      = 0U;
            g_mod_state   = MOD_IDLE;
            return;
        }

        case I2C_DFU_CMD_RESET:
        {
            g_tx_buf[0]   = I2C_DFU_STATUS_OK;
            g_tx_buf[1]   = I2C_DFU_STATE_IDLE;
            g_tx_len      = 2U;
            g_last_status = I2C_DFU_STATUS_OK;
            g_mod_state   = MOD_RESET;  /* main loop will call NVIC_SystemReset() */
            return;  /* early return — mod_state handled separately */
        }

        default:
        {
            g_tx_buf[0]   = I2C_DFU_STATUS_ERROR;
            g_tx_buf[1]   = g_dfu_state;
            g_tx_len      = 2U;
            g_last_status = I2C_DFU_STATUS_ERROR;
            g_mod_state   = MOD_IDLE;
            return;
        }
    }
    /*
     * GETSTATUS and GETVERSION are pure reads — g_mod_state and g_rx_buf/
     * g_rx_len must NOT be touched here.  If an ERASE or DNLOAD is queued
     * (MOD_CMD_READY / MOD_BUSY), those fields belong to that pending op.
     * MANIFEST and RESET return early above.
     */
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

void I2C_DFU_Init(I2C_HandleTypeDef *hi2c)
{
    /* Expose via the global pointer so callbacks can use GLOBAL_I2C_DEVICE */
    GLOBAL_I2C_DEVICE = hi2c;

    g_mod_state   = MOD_IDLE;
    g_dfu_state   = I2C_DFU_STATE_IDLE;
    g_last_status = I2C_DFU_STATUS_OK;
    g_rx_len      = 0U;
    g_rx_step     = 0;

    /* Default transmit response: OK + IDLE */
    g_tx_buf[0] = I2C_DFU_STATUS_OK;
    g_tx_buf[1] = I2C_DFU_STATE_IDLE;
    g_tx_len    = 2U;

    /*
     * Reconfigure as a 7-bit slave at DFU_I2C_ADDRESS (defined in main.h).
     * HAL_I2C_DeInit() / HAL_I2C_Init() cycle re-runs MspInit so clocks,
     * GPIO and NVIC are all correctly (re-)enabled.
     */
    HAL_I2C_DeInit(hi2c);

    hi2c->Init.Timing          = 0x10805D88U; /* Same timing as original MX init */
    hi2c->Init.OwnAddress1     = (DFU_I2C_ADDRESS << 1U);
    hi2c->Init.AddressingMode  = I2C_ADDRESSINGMODE_7BIT;
    hi2c->Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
    hi2c->Init.OwnAddress2     = 0U;
    hi2c->Init.OwnAddress2Masks= I2C_OA2_NOMASK;
    hi2c->Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
    hi2c->Init.NoStretchMode   = I2C_NOSTRETCH_DISABLE;

    if (HAL_I2C_Init(hi2c) != HAL_OK)                                         { Error_Handler(); }
    if (HAL_I2CEx_ConfigAnalogFilter(hi2c, I2C_ANALOGFILTER_ENABLE) != HAL_OK) { Error_Handler(); }
    if (HAL_I2CEx_ConfigDigitalFilter(hi2c, 0U) != HAL_OK)                    { Error_Handler(); }

    /* Start listening for the first transaction from the I2C master */
    if (HAL_I2C_EnableListen_IT(hi2c) != HAL_OK)                              { Error_Handler(); }
}

void I2C_DFU_Process(void)
{
    if (g_mod_state == MOD_CMD_READY)
    {
        g_mod_state = MOD_BUSY;
        process_command();
    }

    if (g_mod_state == MOD_RESET)
    {
        /* Small delay lets the master complete its status read before we reset */
        HAL_Delay(20U);
        NVIC_SystemReset();
    }
}

/* -------------------------------------------------------------------------
 * HAL I2C callbacks  (override weak symbols in stm32l4xx_hal_i2c.c)
 * ---------------------------------------------------------------------- */

/**
 * @brief  Address-match callback — fired when the master addresses us.
 *
 *         For master WRITE (TransferDirection == I2C_DIRECTION_TRANSMIT):
 *           Receive exactly 1 byte (the command byte) with I2C_FIRST_FRAME.
 *           SlaveRxCpltCallback will extend the receive based on the command.
 *           Receiving only 1 byte ensures the receive ALWAYS completes normally
 *           (no partial-receive / XferCount edge cases from the HAL).
 *
 *         For master READ (TransferDirection == I2C_DIRECTION_RECEIVE):
 *           g_tx_buf is always pre-populated by process_inline() or by the
 *           previous flash operation, so transmit it immediately.
 */
void HAL_I2C_AddrCallback(I2C_HandleTypeDef *hi2c,
                           uint8_t TransferDirection,
                           uint16_t AddrMatchCode)
{
    (void)AddrMatchCode;

    if (hi2c->Instance != GLOBAL_I2C_DEVICE->Instance) { return; }

    if (TransferDirection == I2C_DIRECTION_TRANSMIT)
    {
        /*
         * Master WRITES → receive the command byte into g_inline_cmd.
         * Using a dedicated byte (not g_rx_buf[0]) ensures that a GETSTATUS
         * or GETVERSION arriving while an ERASE/DNLOAD is queued never
         * corrupts the pending command data in g_rx_buf.
         */
        g_rx_step = 0;
        HAL_I2C_Slave_Seq_Receive_IT(hi2c, &g_inline_cmd, 1U, I2C_FIRST_FRAME);
    }
    else
    {
        /* Master READS → transmit the already-prepared response buffer */
        HAL_I2C_Slave_Sequential_Transmit_IT(hi2c,
                                              g_tx_buf,
                                              g_tx_len,
                                              I2C_FIRST_AND_LAST_FRAME);
    }
}

/**
 * @brief  Called when the current sequential receive count is exactly met.
 *
 *         This callback is called from ISR context.  The lock is released by
 *         I2C_ITSlaveSeqCplt() before invoking us, so it is safe to issue
 *         another HAL_I2C_Slave_Seq_Receive_IT() call from here.
 *
 *         g_rx_step == 0  Command byte received (always exactly 1 byte).
 *           Single-byte commands: process inline immediately — fills g_tx_buf
 *             so the response is ready before the master issues its read.
 *           Multi-byte commands: set up the next receive phase.
 *
 *         g_rx_step == 1  Second phase complete.
 *           ERASE: 4-byte address received.  Pre-set BUSY response; main
 *             loop performs the flash erase.
 *           DNLOAD: 6-byte header tail received.  Extend receive for payload.
 *
 *         g_rx_step == 2  DNLOAD payload received.  Pre-set BUSY response;
 *           main loop performs the flash write.
 */
void HAL_I2C_SlaveRxCpltCallback(I2C_HandleTypeDef *hi2c)
{
    if (hi2c->Instance != GLOBAL_I2C_DEVICE->Instance) { return; }

    if (g_rx_step == 0)
    {
        /* ---- Command byte phase ---------------------------------------- */
        /* cmd was received into g_inline_cmd (NOT g_rx_buf) in AddrCallback */
        uint8_t cmd = g_inline_cmd;

        switch (cmd)
        {
            case I2C_DFU_CMD_ERASE:
                /* Copy cmd into g_rx_buf and receive the 4-byte address */
                g_rx_buf[CMD_OFFSET] = cmd;
                g_rx_len  = 0U;
                g_rx_step = 1;
                HAL_I2C_Slave_Seq_Receive_IT(hi2c,
                                              g_rx_buf + 1U,
                                              4U,
                                              I2C_LAST_FRAME);
                return;

            case I2C_DFU_CMD_DNLOAD:
                /* Copy cmd into g_rx_buf and receive the remaining header */
                g_rx_buf[CMD_OFFSET] = cmd;
                g_rx_len  = 0U;
                g_rx_step = 1;
                HAL_I2C_Slave_Seq_Receive_IT(hi2c,
                                              g_rx_buf + 1U,
                                              (uint16_t)(HDR_SIZE - 1U),
                                              I2C_NEXT_FRAME);
                return;

            default:
                /*
                 * Inline command (GETSTATUS, GETVERSION, MANIFEST, RESET).
                 * Process immediately — g_rx_buf and g_rx_len are NOT touched,
                 * so any pending ERASE/DNLOAD in g_rx_buf is fully preserved.
                 */
                g_rx_step = 0;
                process_inline(cmd);
                return;
        }
    }
    else if (g_rx_step == 1)
    {
        /* ---- Second phase ---------------------------------------------- */
        uint8_t cmd = g_rx_buf[CMD_OFFSET];

        if (cmd == I2C_DFU_CMD_ERASE)
        {
            /* Full ERASE packet: 1 cmd + 4 addr = 5 bytes */
            g_rx_len  = 5U;
            g_rx_step = 0;
            /* Pre-populate BUSY so any immediate status read is correct */
            g_tx_buf[0]   = I2C_DFU_STATUS_BUSY;
            g_tx_buf[1]   = I2C_DFU_STATE_DNBUSY;
            g_tx_len      = 2U;
            g_dfu_state   = I2C_DFU_STATE_DNBUSY;
            g_last_status = I2C_DFU_STATUS_BUSY;
            if (g_mod_state == MOD_IDLE)
            {
                g_mod_state = MOD_CMD_READY;
            }
        }
        else  /* DNLOAD header tail received */
        {
            uint16_t data_len = 0U;
            memcpy(&data_len, &g_rx_buf[LEN_OFFSET], sizeof(data_len));

            if ((data_len == 0U) || (data_len > (uint16_t)I2C_DFU_MAX_XFER_SIZE))
            {
                /* Bad length rejected immediately */
                g_rx_step     = 0;
                g_tx_buf[0]   = I2C_DFU_STATUS_ERROR;
                g_tx_buf[1]   = g_dfu_state;
                g_tx_len      = 2U;
                g_last_status = I2C_DFU_STATUS_ERROR;
                return;
            }

            /* Receive the firmware payload */
            g_rx_step = 2;
            HAL_I2C_Slave_Seq_Receive_IT(hi2c,
                                          g_rx_buf + HDR_SIZE,
                                          data_len,
                                          I2C_LAST_FRAME);
        }
    }
    else  /* g_rx_step == 2 — DNLOAD payload received */
    {
        uint16_t data_len = 0U;
        memcpy(&data_len, &g_rx_buf[LEN_OFFSET], sizeof(data_len));
        g_rx_len  = (uint16_t)(HDR_SIZE + data_len);
        g_rx_step = 0;
        /* Pre-populate BUSY so any immediate status read is correct */
        g_tx_buf[0]   = I2C_DFU_STATUS_BUSY;
        g_tx_buf[1]   = I2C_DFU_STATE_DNBUSY;
        g_tx_len      = 2U;
        g_dfu_state   = I2C_DFU_STATE_DNBUSY;
        g_last_status = I2C_DFU_STATUS_BUSY;
        if (g_mod_state == MOD_IDLE)
        {
            g_mod_state = MOD_CMD_READY;
        }
    }
}

/**
 * @brief  Called after a STOP condition ends the current transaction.
 *
 *         With the 1-byte-first receive strategy, every receive phase
 *         completes normally (SlaveRxCpltCallback fires for each phase).
 *         This callback therefore only needs to reset state and re-arm.
 */
void HAL_I2C_ListenCpltCallback(I2C_HandleTypeDef *hi2c)
{
    if (hi2c->Instance != GLOBAL_I2C_DEVICE->Instance) { return; }

    /* Reset step counter in case a transaction was truncated unexpectedly */
    g_rx_step = 0;

    /* Re-arm the listener so we are ready for the next transaction */
    HAL_I2C_EnableListen_IT(hi2c);
}

/**
 * @brief  Called when the transmit of the response buffer completes.
 *         Generate a NACK to signal end-of-data if the master continues
 *         clocking, then let ListenCpltCallback re-arm the listener.
 */
void HAL_I2C_SlaveTxCpltCallback(I2C_HandleTypeDef *hi2c)
{
    if (hi2c->Instance != GLOBAL_I2C_DEVICE->Instance) { return; }
    __HAL_I2C_GENERATE_NACK(hi2c);
}

/**
 * @brief  I2C error callback.
 *
 *         HAL_I2C_ERROR_AF is expected in two situations:
 *           - TX side: master NACKs after reading all response bytes (normal).
 *           - RX side: master stopped a transaction early (unexpected but
 *             recoverable — reset step counter and re-arm).
 *
 *         HAL_I2C_ERROR_BERR (bus error) is handled by a DeInit/Init cycle.
 */
void HAL_I2C_ErrorCallback(I2C_HandleTypeDef *hi2c)
{
    if (hi2c->Instance != GLOBAL_I2C_DEVICE->Instance) { return; }

    uint32_t err = HAL_I2C_GetError(hi2c);

    if (err == HAL_I2C_ERROR_AF)
    {
        /* Normal NACK from master or truncated write — clear flag and recover */
        __HAL_I2C_CLEAR_FLAG(hi2c, I2C_FLAG_AF);
    }
    else if (err == HAL_I2C_ERROR_BERR)
    {
        /* Bus error — reinitialise the peripheral */
        HAL_I2C_DeInit(hi2c);
        HAL_I2C_Init(hi2c);
    }
    else
    {
        /* Unexpected error — reset handle state */
        __HAL_I2C_RESET_HANDLE_STATE(hi2c);
    }

    /* Reset step counter and re-arm listen mode */
    g_rx_step   = 0;
    g_rx_len    = 0U;
    HAL_I2C_EnableListen_IT(hi2c);
}
