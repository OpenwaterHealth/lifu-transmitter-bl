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

static I2C_HandleTypeDef    *g_hi2c       = NULL;
static volatile mod_state_t  g_mod_state  = MOD_IDLE;

/* DFU-level state (reported in every read response) */
static uint8_t  g_dfu_state  = I2C_DFU_STATE_IDLE;
static uint8_t  g_last_status = I2C_DFU_STATUS_OK;

/* Receive buffer — filled by ISR, consumed by I2C_DFU_Process() */
static uint8_t   g_rx_buf[RX_BUF_SIZE];
static uint16_t  g_rx_len = 0U;  /* actual bytes received in last write txn */

/* Transmit buffer — populated by process_command(), sent by ISR */
static uint8_t   g_tx_buf[4U];   /* [status:1][state:1] + 2 spare */
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
 * Public API
 * ---------------------------------------------------------------------- */

void I2C_DFU_Init(I2C_HandleTypeDef *hi2c)
{
    g_hi2c        = hi2c;
    g_mod_state   = MOD_IDLE;
    g_dfu_state   = I2C_DFU_STATE_IDLE;
    g_last_status = I2C_DFU_STATUS_OK;
    g_rx_len      = 0U;

    /* Default transmit response: OK + IDLE */
    g_tx_buf[0] = I2C_DFU_STATUS_OK;
    g_tx_buf[1] = I2C_DFU_STATE_IDLE;
    g_tx_len    = 2U;

    /*
     * Reconfigure I2C1 as a 7-bit slave at I2C_DFU_SLAVE_ADDR.
     * HAL_I2C_DeInit() calls HAL_I2C_MspDeInit() (disables clock / GPIO /
     * NVIC), and HAL_I2C_Init() calls HAL_I2C_MspInit() to re-enable them.
     */
    HAL_I2C_DeInit(hi2c);

    hi2c->Init.Timing          = 0x10805D88U; /* Same timing as original MX init */
    hi2c->Init.OwnAddress1     = (I2C_DFU_SLAVE_ADDR << 1U);
    hi2c->Init.AddressingMode  = I2C_ADDRESSINGMODE_7BIT;
    hi2c->Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
    hi2c->Init.OwnAddress2     = 0U;
    hi2c->Init.OwnAddress2Masks= I2C_OA2_NOMASK;
    hi2c->Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
    hi2c->Init.NoStretchMode   = I2C_NOSTRETCH_DISABLE;

    if (HAL_I2C_Init(hi2c) != HAL_OK)                                    { Error_Handler(); }
    if (HAL_I2CEx_ConfigAnalogFilter(hi2c, I2C_ANALOGFILTER_ENABLE) != HAL_OK) { Error_Handler(); }
    if (HAL_I2CEx_ConfigDigitalFilter(hi2c, 0U) != HAL_OK)               { Error_Handler(); }

    /* Start listening for the first transaction from the I2C master */
    if (HAL_I2C_EnableListen_IT(hi2c) != HAL_OK)                         { Error_Handler(); }
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
 *         Set up either a sequential receive or transmit depending on
 *         the transfer direction signalled by the master.
 */
void HAL_I2C_AddrCallback(I2C_HandleTypeDef *hi2c,
                           uint8_t TransferDirection,
                           uint16_t AddrMatchCode)
{
    (void)AddrMatchCode;

    if (hi2c->Instance != I2C1) { return; }

    if (TransferDirection == I2C_DIRECTION_RECEIVE)
    {
        /* Master is writing a command packet to us */
        g_rx_len = 0U;
        HAL_I2C_Slave_Sequential_Receive_IT(hi2c,
                                             g_rx_buf,
                                             RX_BUF_SIZE,
                                             I2C_FIRST_AND_LAST_FRAME);
    }
    else
    {
        /* Master is reading our response */
        HAL_I2C_Slave_Sequential_Transmit_IT(hi2c,
                                              g_tx_buf,
                                              g_tx_len,
                                              I2C_FIRST_AND_LAST_FRAME);
    }
}

/**
 * @brief  Called when the entire requested receive buffer is filled.
 *         This fires when the master sends exactly RX_BUF_SIZE bytes
 *         (uncommon in practice; most commands are much shorter).
 */
void HAL_I2C_SlaveRxCpltCallback(I2C_HandleTypeDef *hi2c)
{
    if (hi2c->Instance != I2C1) { return; }

    g_rx_len = (uint16_t)RX_BUF_SIZE;

    if (g_mod_state == MOD_IDLE)
    {
        g_mod_state = MOD_CMD_READY;
    }
}

/**
 * @brief  Called after a STOP condition ends the current transaction.
 *         This fires for both write and read transactions.
 *
 *         For write transactions where the master sent fewer bytes than
 *         RX_BUF_SIZE (the normal case), XferCount holds the number of
 *         bytes NOT yet received, so actual_received = RX_BUF_SIZE - XferCount.
 */
void HAL_I2C_ListenCpltCallback(I2C_HandleTypeDef *hi2c)
{
    if (hi2c->Instance != I2C1) { return; }

    /* If g_rx_len was not already set by SlaveRxCpltCallback, compute it
     * from the remaining XferCount (partial receive before STOP). */
    if (g_rx_len == 0U)
    {
        uint32_t remaining = hi2c->XferCount;
        if (remaining < (uint32_t)RX_BUF_SIZE)
        {
            g_rx_len = (uint16_t)((uint32_t)RX_BUF_SIZE - remaining);
        }
    }

    if ((g_rx_len > 0U) && (g_mod_state == MOD_IDLE))
    {
        g_mod_state = MOD_CMD_READY;
    }

    /* Re-arm the listener so we are ready for the next transaction */
    HAL_I2C_EnableListen_IT(hi2c);
}

/**
 * @brief  Called when the transmit of the response buffer completes.
 *         Nothing to do here; ListenCpltCallback will re-arm the listener.
 */
void HAL_I2C_SlaveTxCpltCallback(I2C_HandleTypeDef *hi2c)
{
    (void)hi2c;
}

/**
 * @brief  I2C error callback.
 *
 *         HAL_I2C_ERROR_AF on the transmit side is expected when the master
 *         NACKs after reading all response bytes — not a real error.
 *
 *         For receive-side AF (master stopped before we expected), recover
 *         the partial byte count and treat it as a normal end of transaction.
 */
void HAL_I2C_ErrorCallback(I2C_HandleTypeDef *hi2c)
{
    if (hi2c->Instance != I2C1) { return; }

    uint32_t err = HAL_I2C_GetError(hi2c);

    if (err == HAL_I2C_ERROR_AF)
    {
        /* Recover partial receive if applicable */
        if (g_rx_len == 0U)
        {
            uint32_t remaining = hi2c->XferCount;
            if (remaining < (uint32_t)RX_BUF_SIZE)
            {
                g_rx_len = (uint16_t)((uint32_t)RX_BUF_SIZE - remaining);
            }
        }

        if ((g_rx_len > 0U) && (g_mod_state == MOD_IDLE))
        {
            g_mod_state = MOD_CMD_READY;
        }
    }
    else
    {
        /* Unexpected error — reset peripheral state machine */
        __HAL_I2C_RESET_HANDLE_STATE(hi2c);
        g_rx_len    = 0U;
        g_mod_state = MOD_IDLE;
    }

    /* Always re-arm so we don't get stuck */
    HAL_I2C_EnableListen_IT(hi2c);
}
