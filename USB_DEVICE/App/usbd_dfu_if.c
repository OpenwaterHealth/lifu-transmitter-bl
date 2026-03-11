/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : usbd_dfu_if.c
  * @brief          : Usb device for Download Firmware Update.
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
#include "usbd_dfu_if.h"

/* USER CODE BEGIN INCLUDE */
#include "main.h"
#include "memory_map.h"

/* USER CODE END INCLUDE */

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/

/* USER CODE BEGIN PV */
/* Private variables ---------------------------------------------------------*/

#define FLASH_DESC_STR      "@Firmware/0x08017800/1*2Kg,160*2Kg"
#define FLASH_ERASE_TIME    (uint16_t)50
#define FLASH_PROGRAM_TIME  (uint16_t)50                                                             

#define DFU_META_START_ADDR METADATA_ADDRESS
#define DFU_META_END_ADDR   (METADATA_ADDRESS + FLASH_PAGE_SIZE)
#define DFU_APP_START_ADDR  USBD_DFU_APP_DEFAULT_ADD
#define DFU_APP_SIZE_BYTES  APPLICATION_MAX_SIZE
#define DFU_APP_END_ADDR    (DFU_APP_START_ADDR + DFU_APP_SIZE_BYTES)
#define DFU_ERASE_ALL_CMD_ADDR  0xFFFFFFFFU

/* USER CODE END PV */

/** @addtogroup STM32_USB_OTG_DEVICE_LIBRARY
  * @brief Usb device.
  * @{
  */

/** @defgroup USBD_DFU
  * @brief Usb DFU device module.
  * @{
  */

/** @defgroup USBD_DFU_Private_TypesDefinitions
  * @brief Private types.
  * @{
  */

/* USER CODE BEGIN PRIVATE_TYPES */

/* USER CODE END PRIVATE_TYPES */

/**
  * @}
  */

/** @defgroup USBD_DFU_Private_Defines
  * @brief Private defines.
  * @{
  */

#define FLASH_DESC_STR      "@Internal Flash   /0x08000000/03*016Ka,01*016Kg,01*064Kg,07*128Kg,04*016Kg,01*064Kg,07*128Kg"

/* USER CODE BEGIN PRIVATE_DEFINES */

/* USER CODE END PRIVATE_DEFINES */

/**
  * @}
  */

/** @defgroup USBD_DFU_Private_Macros
  * @brief Private macros.
  * @{
  */

/* USER CODE BEGIN PRIVATE_MACRO */

/* USER CODE END PRIVATE_MACRO */

/**
  * @}
  */

/** @defgroup USBD_DFU_Private_Variables
  * @brief Private variables.
  * @{
  */

/* USER CODE BEGIN PRIVATE_VARIABLES */

/* USER CODE END PRIVATE_VARIABLES */

/**
  * @}
  */

/** @defgroup USBD_DFU_Exported_Variables
  * @brief Public variables.
  * @{
  */

extern USBD_HandleTypeDef hUsbDeviceFS;

/* USER CODE BEGIN EXPORTED_VARIABLES */

/* USER CODE END EXPORTED_VARIABLES */

/**
  * @}
  */

/** @defgroup USBD_DFU_Private_FunctionPrototypes
  * @brief Private functions declaration.
  * @{
  */

static uint16_t MEM_If_Init_FS(void);
static uint16_t MEM_If_Erase_FS(uint32_t Add);
static uint16_t MEM_If_Write_FS(uint8_t *src, uint8_t *dest, uint32_t Len);
static uint8_t *MEM_If_Read_FS(uint8_t *src, uint8_t *dest, uint32_t Len);
static uint16_t MEM_If_DeInit_FS(void);
static uint16_t MEM_If_GetStatus_FS(uint32_t Add, uint8_t Cmd, uint8_t *buffer);

/* USER CODE BEGIN PRIVATE_FUNCTIONS_DECLARATION */

static uint32_t GetPage(uint32_t Addr)
{
  uint32_t page = 0;
  
  if (Addr < (FLASH_BASE + FLASH_BANK_SIZE))
  {
    /* Bank 1 */
    page = (Addr - FLASH_BASE) / FLASH_PAGE_SIZE;
  }
  else
  {
    /* Bank 2 */
    page = (Addr - (FLASH_BASE + FLASH_BANK_SIZE)) / FLASH_PAGE_SIZE;
  }
  
  return page;
}

static uint8_t is_dfu_writable_addr(uint32_t addr)
{
  if ((addr >= DFU_META_START_ADDR) && (addr < DFU_META_END_ADDR))
  {
    return 1U;
  }
  if ((addr >= DFU_APP_START_ADDR) && (addr < DFU_APP_END_ADDR))
  {
    return 1U;
  }
  return 0U;
}

static void dfu_led_set_idle(void)
{
  HAL_GPIO_WritePin(LD_HB_GPIO_Port, LD_HB_Pin, GPIO_PIN_RESET);
}

static void dfu_led_toggle_active(void)
{
  HAL_GPIO_TogglePin(LD_HB_GPIO_Port, LD_HB_Pin);
}

static void dfu_led_set_active_on(void)
{
  HAL_GPIO_WritePin(LD_HB_GPIO_Port, LD_HB_Pin, GPIO_PIN_SET);
}

static void dfu_led_set_error(void)
{
  HAL_GPIO_WritePin(LD_HB_GPIO_Port, LD_HB_Pin, GPIO_PIN_SET);
}

/* USER CODE END PRIVATE_FUNCTIONS_DECLARATION */

/**
  * @}
  */

#if defined ( __ICCARM__ ) /* IAR Compiler */
  #pragma data_alignment=4
#endif
__ALIGN_BEGIN USBD_DFU_MediaTypeDef USBD_DFU_fops_FS __ALIGN_END =
{
   (uint8_t*)FLASH_DESC_STR,
    MEM_If_Init_FS,
    MEM_If_DeInit_FS,
    MEM_If_Erase_FS,
    MEM_If_Write_FS,
    MEM_If_Read_FS,
    MEM_If_GetStatus_FS
};

/* Private functions ---------------------------------------------------------*/
/**
  * @brief  Memory initialization routine.
  * @retval USBD_OK if operation is successful, MAL_FAIL else.
  */
uint16_t MEM_If_Init_FS(void)
{
  /* USER CODE BEGIN 0 */
  dfu_led_set_idle();
  HAL_FLASH_Unlock();
  return (USBD_OK);
  /* USER CODE END 0 */
}

/**
  * @brief  De-Initializes Memory
  * @retval USBD_OK if operation is successful, MAL_FAIL else
  */
uint16_t MEM_If_DeInit_FS(void)
{
  /* USER CODE BEGIN 1 */
  HAL_FLASH_Lock();
  dfu_led_set_idle();
  return (USBD_OK);
  /* USER CODE END 1 */
}

/**
  * @brief  Erase sector.
  * @param  Add: Address of sector to be erased.
  * @retval 0 if operation is successful, MAL_FAIL else.
  */
uint16_t MEM_If_Erase_FS(uint32_t Add)
{
  /* USER CODE BEGIN 2 */

  uint32_t PageError = 0U;
  uint32_t page_addr;
  
  uint32_t FirstPage = 0, BankNumber = 0;

  /* Variable contains Flash operation status */
  HAL_StatusTypeDef status = HAL_ERROR;
  FLASH_EraseInitTypeDef eraseinitstruct;

  dfu_led_toggle_active();

  if (Add == DFU_ERASE_ALL_CMD_ADDR)
  {
    eraseinitstruct.TypeErase = FLASH_TYPEERASE_PAGES;
    eraseinitstruct.NbPages = 1U;
    
    for (page_addr = DFU_APP_START_ADDR; page_addr < DFU_APP_END_ADDR; page_addr += FLASH_PAGE_SIZE)
    {
      FirstPage = GetPage(page_addr);
      BankNumber = FLASH_BANK_1;

      eraseinitstruct.Banks = BankNumber;
      eraseinitstruct.Page = FirstPage;

      __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_WRPERR | FLASH_FLAG_PROGERR);
      status = HAL_FLASHEx_Erase(&eraseinitstruct, &PageError);
      if (status != HAL_OK)
      {
        dfu_led_set_error();
        return USBD_FAIL;
      }
    }
    dfu_led_set_active_on();
    return USBD_OK;
  }

  page_addr = Add & ~(FLASH_PAGE_SIZE - 1U);
  if (is_dfu_writable_addr(page_addr) == 0U)
  {
    dfu_led_set_error();
    return USBD_FAIL;
  }

  eraseinitstruct.TypeErase = FLASH_TYPEERASE_PAGES;  
  FirstPage = GetPage(page_addr);
  BankNumber = FLASH_BANK_1;
  eraseinitstruct.Banks = BankNumber;
  eraseinitstruct.Page = FirstPage;
  eraseinitstruct.NbPages = 1U;
  __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_WRPERR | FLASH_FLAG_PROGERR);
  status = HAL_FLASHEx_Erase(&eraseinitstruct, &PageError);
  
  if (status != HAL_OK)
  {
    dfu_led_set_error();
    return USBD_FAIL;
  }
  dfu_led_set_active_on();
  return (USBD_OK);
  /* USER CODE END 2 */
}

/**
  * @brief  Memory write routine.
  * @param  src: Pointer to the source buffer. Address to be written to.
  * @param  dest: Pointer to the destination buffer.
  * @param  Len: Number of data to be written (in bytes).
  * @retval USBD_OK if operation is successful, MAL_FAIL else.
  */
uint16_t MEM_If_Write_FS(uint8_t *src, uint8_t *dest, uint32_t Len)
{
  /* USER CODE BEGIN 3 */
  
  uint32_t dst_addr = (uint32_t)dest;
  uint32_t i = 0;
  uint64_t doubleword = 0xFFFFFFFFFFFFFFFFULL;

  dfu_led_toggle_active();

  if (((dst_addr & 7U) != 0U) || (Len == 0U))
  {
    dfu_led_set_error();
    return USBD_FAIL;
  }

  if ((is_dfu_writable_addr(dst_addr) == 0U) || (is_dfu_writable_addr((dst_addr + Len) - 1U) == 0U))
  {
    dfu_led_set_error();
    return USBD_FAIL;
  }

  __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_WRPERR | FLASH_FLAG_PROGERR);
  
  for(i = 0; i < Len; i+=8)
  {
    doubleword = 0xFFFFFFFFFFFFFFFFULL;
    if ((Len - i) >= 8U)
    {
      ((uint8_t *)&doubleword)[0] = src[i + 0U];
      ((uint8_t *)&doubleword)[1] = src[i + 1U];
      ((uint8_t *)&doubleword)[2] = src[i + 2U];
      ((uint8_t *)&doubleword)[3] = src[i + 3U];
      ((uint8_t *)&doubleword)[4] = src[i + 4U];
      ((uint8_t *)&doubleword)[5] = src[i + 5U];
      ((uint8_t *)&doubleword)[6] = src[i + 6U];
      ((uint8_t *)&doubleword)[7] = src[i + 7U];
    }
    else
    {
      uint32_t tail;
      for (tail = 0U; tail < (Len - i); ++tail)
      {
        ((uint8_t *)&doubleword)[tail] = src[i + tail];
      }
    }

    if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, dst_addr + i, doubleword) != HAL_OK)
    {
      dfu_led_set_error();
      return USBD_FAIL;
    }

    if (*(uint64_t *)(void *)(dst_addr + i) != doubleword)
    {
      dfu_led_set_error();
      return USBD_FAIL;
    }
  }
  dfu_led_set_active_on();
  return (USBD_OK);
  /* USER CODE END 3 */
}

/**
  * @brief  Memory read routine.
  * @param  src: Pointer to the source buffer. Address to be written to.
  * @param  dest: Pointer to the destination buffer.
  * @param  Len: Number of data to be read (in bytes).
  * @retval Pointer to the physical address where data should be read.
  */
uint8_t *MEM_If_Read_FS(uint8_t *src, uint8_t *dest, uint32_t Len)
{
  /* Return a valid address to avoid HardFault */
  /* USER CODE BEGIN 4 */
  uint32_t i = 0;
  uint8_t *psrc = src;

  dfu_led_toggle_active();
  
  for(i = 0; i < Len; i++)
  {
    dest[i] = *psrc++;
  }
  dfu_led_set_active_on();
  /* Return a valid address to avoid HardFault */
  return (uint8_t*)(dest); 
  /* USER CODE END 4 */
}

/**
  * @brief  Get status routine
  * @param  Add: Address to be read from
  * @param  Cmd: Number of data to be read (in bytes)
  * @param  buffer: used for returning the time necessary for a program or an erase operation
  * @retval USBD_OK if operation is successful
  */
uint16_t MEM_If_GetStatus_FS(uint32_t Add, uint8_t Cmd, uint8_t *buffer)
{
  /* USER CODE BEGIN 5 */
  switch (Cmd)
  {
    case DFU_MEDIA_PROGRAM:
      buffer[1] = (uint8_t)FLASH_PROGRAM_TIME;
      buffer[2] = (uint8_t)(FLASH_PROGRAM_TIME >> 8);
      buffer[3] = 0;  
    break;

    case DFU_MEDIA_ERASE:
      buffer[1] = (uint8_t)FLASH_ERASE_TIME;
      buffer[2] = (uint8_t)(FLASH_ERASE_TIME >> 8);
      buffer[3] = 0;
    break;

    default:
      buffer[1] = (uint8_t)FLASH_ERASE_TIME;
      buffer[2] = (uint8_t)(FLASH_ERASE_TIME >> 8);
      buffer[3] = 0;  
      dfu_led_set_idle();
    break;
  }
  return (USBD_OK);
  /* USER CODE END 5 */
}

/* USER CODE BEGIN PRIVATE_FUNCTIONS_IMPLEMENTATION */

/* USER CODE END PRIVATE_FUNCTIONS_IMPLEMENTATION */

/**
  * @}
  */

/**
  * @}
  */

