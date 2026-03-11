/*
 * i2c_dfu_if.h
 *
 * I2C slave DFU interface for transmitters that are not connected to USB.
 *
 * Architecture:
 *   - The first transmitter in the chain has USB and operates as an I2C master.
 *   - Downstream transmitters without USB enter this mode and listen as I2C slaves
 *     on I2C1 (GLOBAL_SCL PB6 / GLOBAL_SDA PB7) at address I2C_DFU_SLAVE_ADDR.
 *   - The upstream transmitter's application firmware relays DFU packets from the
 *     USB host to the downstream transmitter over I2C.
 *
 * Protocol — every exchange is two separate I2C transactions:
 *
 *   1. WRITE transaction (master → slave):
 *        byte[0]   : command byte (see I2C_DFU_CMD_*)
 *        byte[1..4]: target flash address, uint32_t little-endian  (DNLOAD, ERASE)
 *        byte[5..6]: data length,          uint16_t little-endian  (DNLOAD only)
 *        byte[7+]  : data payload                                   (DNLOAD only)
 *
 *   2. READ transaction (master reads from slave):
 *        byte[0]   : status code (see I2C_DFU_STATUS_*)
 *        byte[1]   : DFU state  (see I2C_DFU_STATE_*)
 *
 * The master must allow time for flash erase/program before reading status.
 * A status of I2C_DFU_STATUS_BUSY means the previous operation is still running;
 * the master should retry the read after a short delay.
 */

#ifndef INC_I2C_DFU_IF_H_
#define INC_I2C_DFU_IF_H_

#include "main.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------- */

/** 7-bit I2C slave address used in I2C DFU mode */
#define I2C_DFU_SLAVE_ADDR         0x42U

/** Maximum firmware payload per DNLOAD transaction (bytes).
 *  Must match the transfer size used by the host-side relay firmware. */
#define I2C_DFU_MAX_XFER_SIZE      2048U

/* -------------------------------------------------------------------------
 * Command bytes  (byte[0] of every write transaction)
 * ---------------------------------------------------------------------- */

/** Write firmware data to flash.
 *  Write payload: [addr:4][len:2][data:len] */
#define I2C_DFU_CMD_DNLOAD         0x01U

/** Erase a flash page (or all app pages when addr == 0xFFFFFFFF).
 *  Write payload: [addr:4] */
#define I2C_DFU_CMD_ERASE          0x02U

/** Query current status and DFU state.
 *  Write payload: (none)
 *  Read  response: [status:1][state:1] */
#define I2C_DFU_CMD_GETSTATUS      0x03U

/** Finalise the download — lock flash after all pages have been written.
 *  Write payload: (none) */
#define I2C_DFU_CMD_MANIFEST       0x04U

/** Reset the device.  The slave resets after preparing a final OK response.
 *  Write payload: (none) */
#define I2C_DFU_CMD_RESET          0x05U

/* -------------------------------------------------------------------------
 * Status codes  (byte[0] of every read response)
 * ---------------------------------------------------------------------- */
#define I2C_DFU_STATUS_OK          0x00U  /**< Operation completed successfully */
#define I2C_DFU_STATUS_BUSY        0x01U  /**< Flash operation still in progress — retry */
#define I2C_DFU_STATUS_ERROR       0x02U  /**< Generic / protocol error */
#define I2C_DFU_STATUS_BAD_ADDR    0x03U  /**< Address outside writable region */
#define I2C_DFU_STATUS_FLASH_ERR   0x04U  /**< HAL flash erase/program failure */

/* -------------------------------------------------------------------------
 * DFU state codes  (byte[1] of every read response)
 * ---------------------------------------------------------------------- */
#define I2C_DFU_STATE_IDLE         0x00U  /**< Waiting for first command */
#define I2C_DFU_STATE_DNBUSY       0x01U  /**< Erase / program in progress */
#define I2C_DFU_STATE_DNLOAD_IDLE  0x02U  /**< Page written, ready for next */
#define I2C_DFU_STATE_MANIFEST     0x03U  /**< Finalising */
#define I2C_DFU_STATE_ERROR        0x04U  /**< Unrecoverable error */

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/**
 * @brief  Reconfigure I2C1 as a slave at I2C_DFU_SLAVE_ADDR and start
 *         listening for commands from the upstream transmitter.
 *
 * @param  hi2c  Pointer to the I2C1 handle (hi2c1 from main.c).
 */
void I2C_DFU_Init(I2C_HandleTypeDef *hi2c);

/**
 * @brief  Process any pending DFU command received over I2C.
 *
 * Call this function from the main loop.  It is non-blocking — it returns
 * immediately if no command is pending.  Long-running flash operations
 * (especially full erase) are performed here and include IWDG refreshes.
 */
void I2C_DFU_Process(void);

#ifdef __cplusplus
}
#endif

#endif /* INC_I2C_DFU_IF_H_ */
