/**
 *  @file serial_transport_stm32F103RB.c
 *  @brief Mercury API - Serial transport functions for STM32F103RB board
 *  @author Pallav Joshi
 *  @date 5/16/2016
 */


/*
 * Copyright (c) 2016 ThingMagic, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "tm_reader.h"
#include "STM32F10x.h"

/*********************************************************************  
  Notes:
  The length of the receive and transmit buffers must be a power of 2.
  Each buffer has a next_in and a next_out index.
  If next_in = next_out, the buffer is empty.
  (next_in - next_out) % buffer_size = the number of characters in the buffer.
*********************************************************************/  

#define TBUF_SIZE   256     /*** Must be a power of 2 (2,4,8,16,32,64,128,256,512,...) ***/
#define RBUF_SIZE   256        /*** Must be a power of 2 (2,4,8,16,32,64,128,256,512,...) ***/

/*********************************************************************/  

/*********************************************************************/  

#if TBUF_SIZE < 2
#error TBUF_SIZE is too small.  It must be larger than 1.
#elif ((TBUF_SIZE & (TBUF_SIZE-1)) != 0)
#error TBUF_SIZE must be a power of 2.
#endif

#if RBUF_SIZE < 2
#error RBUF_SIZE is too small.  It must be larger than 1.
#elif ((RBUF_SIZE & (RBUF_SIZE-1)) != 0)
#error RBUF_SIZE must be a power of 2.
#endif

/*********************************************************************/  

/*********************************************************************/  
struct buf_st {
  unsigned int in;                        /* Next In Index                    */
  unsigned int out;                       /* Next Out Index                   */
  char buf [RBUF_SIZE];                   /* Buffer                           */
};

struct buf_st rbuf = { 0, 0,};
#define SIO_RBUFLEN ((unsigned short)(rbuf.in - rbuf.out))

struct buf_st tbuf = { 0, 0,};
#define SIO_TBUFLEN ((unsigned short)(tbuf.in - tbuf.out))

static unsigned int tx_restart = 1;       /* NZ if TX restart is required     */

/*********************************************************************/  

/****************** Delay method ****************/ 
void delay(int dly)
{
    while( dly--);
}


/*********************************************************************/  

/********** USART1_IRQHandler Handles USART1 global interrupt request. ***********/ 

void USART1_IRQHandler (void) {
  volatile unsigned int IIR;
  struct buf_st *p;
	
	IIR = USART1->SR;
	if (IIR & USART_SR_RXNE) 
	{                /* read interrupt  */
		USART1->SR &= ~USART_SR_RXNE;	           /* clear interrupt */
		p = &rbuf;

		if (((p->in - p->out) & ~(RBUF_SIZE-1)) == 0) 
		{
			p->buf [p->in & (RBUF_SIZE-1)] = (USART1->DR & 0x1FF);
			p->in++;
				
			if(p->in == RBUF_SIZE)
				p->in = 0;
    }
	}

	if (IIR & USART_SR_TXE) 
	{
		USART1->SR &= ~USART_SR_TXE;	            /* clear interrupt  */
		p = &tbuf;
		if (p->in != p->out) 
		{
			USART1->DR = (p->buf [p->out & (TBUF_SIZE-1)] & 0x1FF);
			p->out++;
			
			if(p->out == TBUF_SIZE)
				p->out = 0;
			
      tx_restart = 0;
    }
    else 
		{
			tx_restart = 1;
			USART1->CR1 &= ~USART_SR_TXE;           /* disable TX IRQ if nothing to send */
    }
	}
}


/*********************************************************************/  

/****************** SendChar:Sends a character ****************/  
int SendChar (int c) {
	struct buf_st *p = &tbuf;
	if (SIO_TBUFLEN >= TBUF_SIZE)                /* If the buffer is full            */
		return (-1);                               /* return an error value            */
                                                  
	p->buf [p->in & (TBUF_SIZE - 1)] = c;        /* Add data to the transmit buffer. */
	p->in++;
	
	if(p->in == TBUF_SIZE)
		p->in = 0;

	if (tx_restart) 
	{                           /* If TX interrupt is disabled   */
		tx_restart = 0;                           /* enable it                     */
		USART1->CR1 |= USART_SR_TXE;              /* enable TX interrupt           */
  }  

  return (0);
}
/*********************************************************************/  

/****************** GetKey :receive a character ****************/  
int GetKey (void) {
  struct buf_st *p = &rbuf;
	uint8_t receiveByte;

  if (SIO_RBUFLEN == 0)
    return (-1);

  receiveByte = (p->buf [(p->out++) & (RBUF_SIZE - 1)]);
	if(p->out == RBUF_SIZE)
		p->out = 0;
	return  receiveByte;
}
/*********************************************************************/  


/****************** Stub implementation of serial transport layer routines. ****************/  
static TMR_Status
s_open(TMR_SR_SerialTransport *this)
{
 int i;

	tbuf.in = 0;                            /* Clear com buffer indexes           */
  tbuf.out = 0;
  tx_restart = 1;

  rbuf.in = 0;
  rbuf.out = 0;
	
  RCC->APB2ENR |=  (   1UL <<  0);        /* enable clock Alternate Function  */
  AFIO->MAPR   &= ~(   1UL <<  2);        /* clear USART1 remap               */

  RCC->APB2ENR |=  (   1UL <<  2);        /* enable GPIOA clock               */
  GPIOA->CRH   &= ~(0xFFUL <<  4);        /* clear PA9, PA10                  */
  GPIOA->CRH   |=  (0x0BUL <<  4);        /* USART1 Tx (PA9) output push-pull */
  GPIOA->CRH   |=  (0x04UL <<  8);        /* USART1 Rx (PA10) input floating  */

  RCC->APB2ENR |=  (   1UL << 14);        /* enable USART#1 clock             */

  USART1->BRR   = 0x0271;                 /* 115200 baud @ PCLK2 72MHz        */
  USART1->CR1   = ((   1UL <<  2) |       /* enable RX                        */
                   (   1UL <<  3) |       /* enable TX                        */
                   (   1UL <<  5) |       /* enable RXNE Interrupt            */
                   (   1UL <<  7) |       /* enable TXE Interrupt             */
                   (   0UL << 12) );      /* 1 start bit, 8 data bits         */
  USART1->CR2   = 0x0000;                 /* 1 stop bit                       */
  USART1->CR3   = 0x0000;                 /* no flow control                  */
  for (i = 0; i < 0x1000; i++) __NOP();   /* avoid unwanted output            */

  NVIC_EnableIRQ(USART1_IRQn);
  USART1->CR1  |= ((   1UL << 13) );      /* enable USART                     */
	
	return TMR_SUCCESS;

}

  /* This routine should send length bytes, pointed to by message on
   * the serial connection. If the transmission does not complete in
   * timeoutMs milliseconds, it should return TMR_ERROR_TIMEOUT.
   */
static TMR_Status
s_sendBytes(TMR_SR_SerialTransport *this, uint32_t length, 
                uint8_t* message, const uint32_t timeoutMs)
{
	uint32_t i = 0;
	tbuf.in = 0;                              /* Clear com buffer indexes           */
  tbuf.out = 0;
	for (i = 0; i<length; i++)
	{
		SendChar(message[i]);
	}
	rbuf.in = 0;
  rbuf.out = 0;
  return TMR_SUCCESS;
}

/* This routine should receive exactly length bytes on the serial
   * connection and store them into the memory pointed to by
   * message. If the required number of bytes are note received in
   * timeoutMs milliseconds, it should return TMR_ERROR_TIMEOUT.
   */
static TMR_Status
s_receiveBytes(TMR_SR_SerialTransport *this, uint32_t length, 
									 uint32_t* messageLength, uint8_t* message, const uint32_t timeoutMs)
{
	uint32_t i = 0;
	delay(20000000);										/*Wait till the data is ready to be received*/
	while (SIO_RBUFLEN != 0)
	{
		if(i == length )
			break;
		message[i] = GetKey();
		i++;
	}
	
	return TMR_SUCCESS;
}



static TMR_Status
s_setBaudRate(TMR_SR_SerialTransport *this, uint32_t rate)
{
  /* This routine should change the baud rate of the serial connection
   * to the specified rate, or return TMR_ERROR_INVALID if the rate is
   * not supported.
   */
	USART1->BRR   = 72000000 / (long) rate;           /* 115200 baud @ PCLK2 72MHz */
     
	return TMR_SUCCESS;
}


static TMR_Status
s_shutdown(TMR_SR_SerialTransport *this)
{

  /* This routine should close the serial connection and release any
   * acquired resources.
   */

	USART1->CR1 &= ~USART_SR_TXE;     /* disable TX IRQ if nothing to send  */

  return TMR_SUCCESS;
}


static TMR_Status
s_flush(TMR_SR_SerialTransport *this)
{
  /* This routine should empty any input or output buffers in the
   * communication channel. If there are no such buffers, it may do
   * nothing.
   */
	
  return TMR_SUCCESS;
}

/**
 * Initialize a TMR_SR_SerialTransport structure with a given serial device.
 *
 * @param transport The TMR_SR_SerialTransport structure to initialize.
 * @param context A TMR_SR_SerialPortNativeContext structure for the callbacks to use.
 * @param device The path or name of the serial device (@c /dev/ttyS0, @c COM1)
 */

TMR_Status
TMR_SR_SerialTransportNativeInit(TMR_SR_SerialTransport *transport,
                                 TMR_SR_SerialPortNativeContext *context,
                                 const char *device)
{

  /* Each of the callback functions will be passed the transport
   * pointer, and they can use the "cookie" member of the transport
   * structure to store the information specific to the transport,
   * such as a file handle or the memory address of the FIFO.
   */
  
  transport->cookie = context;
  transport->open = s_open;
  transport->sendBytes = s_sendBytes;
  transport->receiveBytes = s_receiveBytes;
  transport->setBaudRate = s_setBaudRate;
  transport->shutdown = s_shutdown;
  transport->flush = s_flush;

  
#if TMR_MAX_SERIAL_DEVICE_NAME_LENGTH > 0
  if (strlen(device) + 1 > TMR_MAX_SERIAL_DEVICE_NAME_LENGTH)
  {
    return TMR_ERROR_INVALID;
  }
  strcpy(context->devicename, device);
  return TMR_SUCCESS;
#else
  /* No space to store the device name, so open it now */
  return s_open(transport);
#endif

}
