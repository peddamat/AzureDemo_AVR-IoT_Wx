/**
*  @file		nm_bus_wrapper_win_uart.c
*  @brief		This module contains NMC1000 bus_wrapper APIs implementation for Windows Uart
*  @author		Dina El Sissy
*  @date		19 Sep 2012
*  @version		1.0
*/
#ifdef CONF_WINC_USE_UART
#include "bus_wrapper/include/nm_bus_wrapper.h"
#include "bsp/include/nm_bsp.h"
#include "simple_uart.h"


#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#define NM_BUS_MAX_TRX_SZ	128
#define NM_UART_READ_RETRIES 10

typedef sint8(*tpfCheckPort)(void);

tstrNmBusCapabilities egstrNmBusCapabilities =
{
	NM_BUS_MAX_TRX_SZ
};

struct simple_uart *uart;
// HANDLE *phUARTPortHandle = 0;
uint8 onchipuart = 0;
uint8 comports[255][3] = {0};
// static DCB defaultDCB;

static sint8 nm_uart_reinit(void *pvConfig)
{
    return M2M_ERR_BUS_FAIL;
}

#define DELM "(COM"
#define EDBG "EDBG"

int get_all_ports(uint8 * arr)
{
        return 0;
}

/*
*	@fn			nm_uart_get_com_port
*	@brief		get the all the available  uart port
*	@version	1.0
*/
static sint8 nm_uart_get_com_port(uint8 * arr)
{
        return 0;
}

/*
*	@fn			nm_uart_init
*	@brief		init uart
*	@param [in]	uint8 comnum
*					COM port number
*	@return		M2M_SUCCESS in case of success and M2M_ERR_BUS_FAIL in case of failure
*	@author		Dina El Sissy
*	@date		19 Sept 2012
*	@version	1.0
*/
static sint8 nm_uart_init(uint8 comnum,uint8 flow)
{
    const char *port = "/dev/tty.Bluetooth-Incoming-Port";
    int baudrate = 115200;
    const char *flags = "8N1";

    sint8 s8Status = M2M_SUCCESS;
    uart = simple_uart_open(port, baudrate, flags);
    if (!uart) {
        fprintf(stderr, "Unable to open %s:%d:%s\n", port, baudrate, flags);
        exit(1);
    }

    return s8Status;
}

/*
*	@fn			nm_uart_read
*	@brief		read from the bus
*	@param [out]uint8 *pu8ReadBuffer
*					Buffer to data
*	@param [in]	sint32 s32ReadSize
*					Size of data
*	@return		M2M_SUCCESS in case of success and M2M_ERR_BUS_FAIL in case of failure
*	@author		Dina El Sissy
*	@date		19 Sept 2012
*	@version	1.0
*/
static sint8 nm_uart_read(uint8 *pu8ReadBuffer, sint32 s32ReadSize)
{
	sint8 s8Ret = M2M_SUCCESS;
    if (simple_uart_read(uart, pu8ReadBuffer, s32ReadSize) == s32ReadSize) {
        return M2M_SUCCESS;
    }
    else {
        return M2M_ERR_BUS_FAIL;
    }
}

/*
*	@fn			nm_uart_write
*	@brief		write to the bus
*	@param [in]	uint8 *pu8Buffer
*					Buffer to data
*	@param [in]	sint32 s32Size
*					Size of data
*	@return		M2M_SUCCESS in case of success and M2M_ERR_BUS_FAIL in case of failure
*	@author		Dina El Sissy
*	@date		19 Sept 2012
*	@version	1.0
*/
static sint8 nm_uart_write(uint8 *pu8Buffer, sint32 s32Size)
{
	sint8 s8Ret = M2M_SUCCESS;
	sint32 s32Status = 0;
	uint32 u32NumBytesWritten;

    if (simple_uart_write(uart, pu8Buffer, s32Size) == s32Size) {
        return M2M_SUCCESS;
    }
    else {
		M2M_ERR("Error writing to PORT\n");
        return M2M_ERR_BUS_FAIL;
    }
}

/*
*	@fn			nm_uart_deinit
*	@brief		deinit the bus
*	@return		M2M_SUCCESS in case of success and M2M_ERR_BUS_FAIL in case of failure
*	@author		Dina El Sissy
*	@date		19 Sept 2012
*	@version	1.0
*/
static sint8 nm_uart_deinit(void)
{
    simple_uart_close(uart);
	return M2M_SUCCESS;
}
/*
*	@fn			nm_bus_get_chip_type
*	@brief		get chip type
*	@return		M2M_SUCCESS in case of success and M2M_ERR_BUS_FAIL in case of failure
*	@author		M.S.M
*	@date		19 Sept 2012
*	@version	1.0
*/
uint8 nm_bus_get_chip_type(void)
{
	return onchipuart;

}
/*
*	@fn			nm_bus_break
*	@return		M2M_SUCCESS in case of success and M2M_ERR_BUS_FAIL in case of failure
*	@author		M.S.M
*	@date		19 Sept 2012
*	@version	1.0
*/
sint8 nm_bus_break(void)
{
    simple_uart_send_break(uart);
	return 0;
}
/*
*	@fn			nm_bus_init
*	@brief		Initialize the bus wrapper
*	@return		M2M_SUCCESS in case of success and M2M_ERR_BUS_FAIL in case of failure
*	@author		Dina El Sissy
*	@date		19 Sept 2012
*	@version	1.0
*/
sint8 nm_bus_init(void *pvPortNum)
{
	uint32 i;
	sint8 result = M2M_SUCCESS;

	if(0 == *((uint8*)pvPortNum))
	{
		M2M_PRINT("Enter port number: \n");
		scanf("%hhu", (uint8*)pvPortNum);
	}
	for(i=0;i<255,comports[i][0]!=0;i++)
	{
		if(*((uint8 *)pvPortNum) == comports[i][0])
		{
			onchipuart = comports[i][1];
			break;
		}
	}
	if(*((uint8*)pvPortNum)>0 && *((uint8*)pvPortNum) <=256)
	{
		result = nm_uart_init(*((uint8*)pvPortNum),comports[i][2]);
	}
	else
	{
		M2M_PRINT(">Invalid port number\n");
		result = M2M_ERR_BUS_FAIL;
	}
	return result;
}

/*
*	@fn			nm_bus_ioctl
*	@brief		send/receive from the bus
*	@param [in]	u8Cmd
*					IOCTL command for the operation
*	@param [in]	pvParameter
*					Arbitrary parameter depending on IOCTL
*	@return		M2M_SUCCESS in case of success and M2M_ERR_BUS_FAIL in case of failure
*	@author		Dina El Sissy
*	@date		19 Sept 2012
*	@version	1.0
*/
sint8 nm_bus_ioctl(uint8 u8Cmd, void* pvParameter)
{
	sint8 s8Ret = 0;
	switch(u8Cmd)
	{
	case NM_BUS_IOCTL_R:
		{
			tstrNmUartDefault *pstrParam = (tstrNmUartDefault *)pvParameter;
			s8Ret = nm_uart_read(pstrParam->pu8Buf, pstrParam ->u16Sz);
		}
		break;
	case NM_BUS_IOCTL_W:
		{
			tstrNmUartDefault *pstrParam = (tstrNmUartDefault *)pvParameter;
			s8Ret = nm_uart_write(pstrParam->pu8Buf, pstrParam ->u16Sz);
		}
		break;
	default:
		s8Ret = M2M_ERR_BUS_FAIL;
		M2M_ERR("invalid ioclt cmd\n");
		break;
	}
	return s8Ret;
}

/*
*	@fn			nm_bus_deinit
*	@brief		De-initialize the bus wrapper
*	@author		Dina El Sissy
*	@date		20 Sept 2012
*	@version	1.0
*/
sint8 nm_bus_deinit(void)
{
	return nm_uart_deinit();
}

/*
*	@fn			nm_bus_reinit
*	@brief		re-initialize the bus wrapper
*	@param [in]	void *config
*					re-init configuration data
*	@return		M2M_SUCCESS in case of success and M2M_ERR_BUS_FAIL in case of failure
*	@author		Dina El Sissy
*	@date		19 Sept 2012
*	@version	1.0
*/
sint8 nm_bus_reinit(void* config)
{
	return nm_uart_reinit(config);
}

/*
*	@fn			port_detect
*	@brief		detecting COM port
*	@param [in]	uint8 *avail
*					pointer to available ports
*	@param [in]	tpfCheckPort pfChkPort
*					pointer to call back function (nm_uart_check_port) to check
*	@return		port number in case of success and 0 in case of failure
*	@author		Dina El Sissy
*	@date		19 Sept 2012
*	@version	1.0
*/
uint8 nm_bus_port_detect(uint8 * avail, tpfCheckPort pfChkPort)
{
	sint8 uart_type = 0;
	sint8 ret = 0;
	int i;
	int k = 0;

	printf("Detecting ports...\n");
	nm_uart_get_com_port((uint8*)comports);
	for(i = 0; (i<255)&&(comports[i][0] != 0); i++)
	{
		ret = nm_bus_init((uint8 *)&comports[i][0]);
		if(ret != M2M_SUCCESS)
		{
			M2M_PRINT(">>(ERR):Connect uart\n");
			continue;
		}
		uart_type =  pfChkPort();
		if (uart_type >= 0) {
			comports[i][1] = uart_type;
			avail[k] = comports[i][0];
			printf("Avail port COM%d\n",avail[k]);
			k++;
		} else {
		}
		nm_bus_deinit();
	}
	if(k == 0)
	{
		M2M_ERR("Failed to find any COM ports\n");
	}
	printf("%d of ports found\n",k);
	return k;
}


#endif /*CONF_WINC_USE_UART*/