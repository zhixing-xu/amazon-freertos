/* Standard includes. */
#include <stdint.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "list.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_DNS.h"
#include "NetworkBufferManagement.h"
#include "NetworkInterface.h"
#include "IPTraceMacroDefaults.h"

#if( ipconfigBYTE_ORDER == pdFREERTOS_LITTLE_ENDIAN )
	#define dnsDNS_PORT						0x3500
	#define dnsONE_QUESTION					0x0100
	#define dnsOUTGOING_FLAGS				0x0001 /* Standard query. */
	#define dnsRX_FLAGS_MASK				0x0f80 /* The bits of interest in the flags field of incoming DNS messages. */
	#define dnsEXPECTED_RX_FLAGS			0x0080 /* Should be a response, without any errors. */
#else
	#define dnsDNS_PORT						0x0035
	#define dnsONE_QUESTION					0x0001
	#define dnsOUTGOING_FLAGS				0x0100 /* Standard query. */
	#define dnsRX_FLAGS_MASK				0x800f /* The bits of interest in the flags field of incoming DNS messages. */
	#define dnsEXPECTED_RX_FLAGS			0x8000 /* Should be a response, without any errors. */

#endif /* ipconfigBYTE_ORDER */

/* The maximum number of times a DNS request should be sent out if a response
is not received, before giving up. */
#ifndef ipconfigDNS_REQUEST_ATTEMPTS
	#define ipconfigDNS_REQUEST_ATTEMPTS		5
#endif

/* If the top two bits in the first character of a name field are set then the
name field is an offset to the string, rather than the string itself. */
#define dnsNAME_IS_OFFSET					( ( uint8_t ) 0xc0 )

/* NBNS flags. */
#define dnsNBNS_FLAGS_RESPONSE				0x8000
#define dnsNBNS_FLAGS_OPCODE_MASK			0x7800
#define dnsNBNS_FLAGS_OPCODE_QUERY			0x0000
#define dnsNBNS_FLAGS_OPCODE_REGISTRATION	0x2800

/* Host types. */
#define dnsTYPE_A_HOST						0x01
#define dnsCLASS_IN							0x01

/* LLMNR constants. */
#define dnsLLMNR_TTL_VALUE					300000
#define dnsLLMNR_FLAGS_IS_REPONSE  			0x8000

/* NBNS constants. */
#define dnsNBNS_TTL_VALUE					3600 /* 1 hour valid */
#define dnsNBNS_TYPE_NET_BIOS				0x0020
#define dnsNBNS_CLASS_IN					0x01
#define dnsNBNS_NAME_FLAGS					0x6000
#define dnsNBNS_ENCODED_NAME_LENGTH			32

/* If the queried NBNS name matches with the device's name,
the query will be responded to with these flags: */
#define dnsNBNS_QUERY_RESPONSE_FLAGS	( 0x8500 )

#if( ipconfigUSE_DNS_CACHE == 1 )
	static uint8_t *prvReadNameField( uint8_t *pucByte, char *pcName, BaseType_t xLen );
	static void prvProcessDNSCache( const char *pcName, uint32_t *pulIP, BaseType_t xLookUp );

	typedef struct xDNS_CACHE_TABLE_ROW
	{
		uint32_t ulIPAddress;		/* The IP address of an ARP cache entry. */
		char pcName[ipconfigDNS_CACHE_NAME_LENGTH];  /* The name of the host */
		uint8_t ucAge;				/* A value that is periodically decremented but can also be refreshed by active communication.  The ARP cache entry is removed if the value reaches zero. */
	} DNSCacheRow_t;

	static DNSCacheRow_t xDNSCache[ ipconfigDNS_CACHE_ENTRIES ];
#endif /* ipconfigUSE_DNS_CACHE == 1 */

#if( ipconfigUSE_LLMNR == 1 )
	const MACAddress_t xLLMNR_MacAdress = { { 0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc } };
#endif	/* ipconfigUSE_LLMNR == 1 */

/*-----------------------------------------------------------*/

#include "pack_struct_start.h"
struct xDNSMessage
{
	uint16_t usIdentifier;
	uint16_t usFlags;
	uint16_t usQuestions;
	uint16_t usAnswers;
	uint16_t usAuthorityRRs;
	uint16_t usAdditionalRRs;
}
#include "pack_struct_end.h"
typedef struct xDNSMessage DNSMessage_t;

/* A DNS query consists of a header, as described in 'struct xDNSMessage'
It is followed by 1 or more queries, each one consisting of a name and a tail,
with two fields: type and class
*/
#include "pack_struct_start.h"
struct xDNSTail
{
	uint16_t usType;
	uint16_t usClass;
}
#include "pack_struct_end.h"
typedef struct xDNSTail DNSTail_t;

#if( ipconfigUSE_LLMNR == 1 )

	#include "pack_struct_start.h"
	struct xLLMNRAnswer
	{
		uint8_t ucNameCode;
		uint8_t ucNameOffset;	/* The name is not repeated in the answer, only the offset is given with "0xc0 <offs>" */
		uint16_t usType;
		uint16_t usClass;
		uint32_t ulTTL;
		uint16_t usDataLength;
		uint32_t ulIPAddress;
	}
	#include "pack_struct_end.h"
	typedef struct xLLMNRAnswer LLMNRAnswer_t;

#endif /* ipconfigUSE_LLMNR == 1 */

#if( ipconfigUSE_NBNS == 1 )

	#include "pack_struct_start.h"
	struct xNBNSRequest
	{
		uint16_t usRequestId;
		uint16_t usFlags;
		uint16_t ulRequestCount;
		uint16_t usAnswerRSS;
		uint16_t usAuthRSS;
		uint16_t usAdditionalRSS;
		uint8_t ucNameSpace;
		uint8_t ucName[ dnsNBNS_ENCODED_NAME_LENGTH ];
		uint8_t ucNameZero;
		uint16_t usType;
		uint16_t usClass;
	}
	#include "pack_struct_end.h"
	typedef struct xNBNSRequest NBNSRequest_t;

	#include "pack_struct_start.h"
	struct xNBNSAnswer
	{
		uint16_t usType;
		uint16_t usClass;
		uint32_t ulTTL;
		uint16_t usDataLength;
		uint16_t usNbFlags;		/* NetBIOS flags 0x6000 : IP-address, big-endian */
		uint32_t ulIPAddress;
	}
	#include "pack_struct_end.h"
	typedef struct xNBNSAnswer NBNSAnswer_t;

#endif /* ipconfigUSE_NBNS == 1 */

/*-----------------------------------------------------------*/

#if( ipconfigUSE_DNS_CACHE == 1 )
	uint32_t FreeRTOS_dnslookup( const char *pcHostName )
	{
	uint32_t ulIPAddress = 0UL;
		prvProcessDNSCache( pcHostName, &ulIPAddress, pdTRUE );
		return ulIPAddress;
	}
#endif /* ipconfigUSE_DNS_CACHE == 1 */


static uint32_t prvParseDNSReply( uint8_t *pucUDPPayloadBuffer, TickType_t xIdentifier )
{
DNSMessage_t *pxDNSMessageHeader;
uint32_t ulIPAddress = 0UL;
#if( ipconfigUSE_LLMNR == 1 )
	char *pcRequestedName = NULL;
#endif
uint8_t *pucByte;
uint16_t x, usDataLength, usQuestions;
#if( ipconfigUSE_LLMNR == 1 )
	uint16_t usType = 0, usClass = 0;
#endif
#if( ipconfigUSE_DNS_CACHE == 1 )
	char pcName[128] = ""; /*_RB_ What is the significance of 128?  Probably too big to go on the stack for a small MCU but don't know how else it could be made re-entrant.  Might be necessary. */
#endif

	pxDNSMessageHeader = ( DNSMessage_t * ) pucUDPPayloadBuffer;

	if( pxDNSMessageHeader->usIdentifier == ( uint16_t ) xIdentifier )
	{
		/* Start at the first byte after the header. */
		pucByte = pucUDPPayloadBuffer + sizeof( DNSMessage_t );

		/* Skip any question records. */
		usQuestions = FreeRTOS_ntohs( pxDNSMessageHeader->usQuestions );
		for( x = 0; x < usQuestions; x++ )
		{
			#if( ipconfigUSE_LLMNR == 1 )
			{
				if( x == 0 )
				{
					pcRequestedName = ( char * ) pucByte;
				}
			}
			#endif

#if( ipconfigUSE_DNS_CACHE == 1 )
			if( x == 0 )
			{
				pucByte = prvReadNameField( pucByte, pcName, sizeof( pcName ) );
			}
			else
#endif /* ipconfigUSE_DNS_CACHE */
			{
				/* Skip the variable length pcName field. */
				pucByte = prvSkipNameField( pucByte );
			}

			#if( ipconfigUSE_LLMNR == 1 )
			{
				/* usChar2u16 returns value in host endianness */
				usType = usChar2u16( pucByte );
				usClass = usChar2u16( pucByte + 2 );
			}
			#endif /* ipconfigUSE_LLMNR */

			/* Skip the type and class fields. */
			pucByte += sizeof( uint32_t );
		}

		/* Search through the answers records. */
		pxDNSMessageHeader->usAnswers = FreeRTOS_ntohs( pxDNSMessageHeader->usAnswers );

		if( ( pxDNSMessageHeader->usFlags & dnsRX_FLAGS_MASK ) == dnsEXPECTED_RX_FLAGS )
		{
			for( x = 0; x < pxDNSMessageHeader->usAnswers; x++ )
			{
				pucByte = prvSkipNameField( pucByte );

				/* Is the type field that of an A record? */
				if( usChar2u16( pucByte ) == dnsTYPE_A_HOST )
				{
					/* This is the required record.  Skip the type, class, and
					time to live fields, plus the first byte of the data
					length. */
					pucByte += ( sizeof( uint32_t ) + sizeof( uint32_t ) + sizeof( uint8_t ) );

					/* Sanity check the data length. */
					if( ( size_t ) *pucByte == sizeof( uint32_t ) )
					{
						/* Skip the second byte of the length. */
						pucByte++;

						/* Copy the IP address out of the record. */
						memcpy( ( void * ) &ulIPAddress, ( void * ) pucByte, sizeof( uint32_t ) );

						#if( ipconfigUSE_DNS_CACHE == 1 )
						{
							prvProcessDNSCache( pcName, &ulIPAddress, pdFALSE );
						}
						#endif /* ipconfigUSE_DNS_CACHE */
						#if( ipconfigDNS_USE_CALLBACKS != 0 )
						{
							/* See if any asynchronous call was made to FreeRTOS_gethostbyname_a() */
							vDNSDoCallback( ( TickType_t ) pxDNSMessageHeader->usIdentifier, pcName, ulIPAddress );
						}
						#endif	/* ipconfigDNS_USE_CALLBACKS != 0 */
					}

					break;
				}
				else
				{
					/* Skip the type, class and time to live fields. */
					pucByte += ( sizeof( uint32_t ) + sizeof( uint32_t ) );

					/* Determine the length of the data in the field. */
					memcpy( ( void * ) &usDataLength, ( void * ) pucByte, sizeof( uint16_t ) );
					usDataLength = FreeRTOS_ntohs( usDataLength );

					/* Jump over the data length bytes, and the data itself. */
					pucByte += usDataLength + sizeof( uint16_t );
				}
			}
		}
#if( ipconfigUSE_LLMNR == 1 )
		else if( usQuestions && ( usType == dnsTYPE_A_HOST ) && ( usClass == dnsCLASS_IN ) )
		{
			/* If this is not a reply to our DNS request, it might an LLMNR
			request. */
			if( xApplicationDNSQueryHook ( ( pcRequestedName + 1 ) ) )
			{
			int16_t usLength;
			NetworkBufferDescriptor_t *pxNewBuffer = NULL;
			NetworkBufferDescriptor_t *pxNetworkBuffer = pxUDPPayloadBuffer_to_NetworkBuffer( pucUDPPayloadBuffer );
			LLMNRAnswer_t *pxAnswer;

				if( ( xBufferAllocFixedSize == pdFALSE ) && ( pxNetworkBuffer != NULL ) )
				{
				BaseType_t xDataLength = pxNetworkBuffer->xDataLength + sizeof( UDPHeader_t ) +
					sizeof( EthernetHeader_t ) + sizeof( IPHeader_t );

					/* The field xDataLength was set to the length of the UDP payload.
					The answer (reply) will be longer than the request, so the packet
					must be duplicaed into a bigger buffer */
					pxNetworkBuffer->xDataLength = xDataLength;
					pxNewBuffer = pxDuplicateNetworkBufferWithDescriptor( pxNetworkBuffer, xDataLength + 16 );
					if( pxNewBuffer != NULL )
					{
					BaseType_t xOffset1, xOffset2;

						xOffset1 = ( BaseType_t ) ( pucByte - pucUDPPayloadBuffer );
						xOffset2 = ( BaseType_t ) ( ( ( uint8_t * ) pcRequestedName ) - pucUDPPayloadBuffer );

						pxNetworkBuffer = pxNewBuffer;
						pucUDPPayloadBuffer = pxNetworkBuffer->pucEthernetBuffer + ipUDP_PAYLOAD_OFFSET_IPv4;

						pucByte = pucUDPPayloadBuffer + xOffset1;
						pcRequestedName = ( char * ) ( pucUDPPayloadBuffer + xOffset2 );
						pxDNSMessageHeader = ( DNSMessage_t * ) pucUDPPayloadBuffer;

					}
					else
					{
						/* Just to indicate that the message may not be answered. */
						pxNetworkBuffer = NULL;
					}
				}
				if( pxNetworkBuffer != NULL )
				{
					pxAnswer = (LLMNRAnswer_t *)pucByte;

					/* We leave 'usIdentifier' and 'usQuestions' untouched */
					vSetField16( pxDNSMessageHeader, DNSMessage_t, usFlags, dnsLLMNR_FLAGS_IS_REPONSE );	/* Set the response flag */
					vSetField16( pxDNSMessageHeader, DNSMessage_t, usAnswers, 1 );	/* Provide a single answer */
					vSetField16( pxDNSMessageHeader, DNSMessage_t, usAuthorityRRs, 0 );	/* No authority */
					vSetField16( pxDNSMessageHeader, DNSMessage_t, usAdditionalRRs, 0 );	/* No additional info */

					pxAnswer->ucNameCode = dnsNAME_IS_OFFSET;
					pxAnswer->ucNameOffset = ( uint8_t )( pcRequestedName - ( char * ) pucUDPPayloadBuffer );

					vSetField16( pxAnswer, LLMNRAnswer_t, usType, dnsTYPE_A_HOST );	/* Type A: host */
					vSetField16( pxAnswer, LLMNRAnswer_t, usClass, dnsCLASS_IN );	/* 1: Class IN */
					vSetField32( pxAnswer, LLMNRAnswer_t, ulTTL, dnsLLMNR_TTL_VALUE );
					vSetField16( pxAnswer, LLMNRAnswer_t, usDataLength, 4 );
					vSetField32( pxAnswer, LLMNRAnswer_t, ulIPAddress, FreeRTOS_ntohl( *ipLOCAL_IP_ADDRESS_POINTER ) );

					usLength = ( int16_t ) ( sizeof( *pxAnswer ) + ( size_t ) ( pucByte - pucUDPPayloadBuffer ) );

					prvReplyDNSMessage( pxNetworkBuffer, usLength );

					if( pxNewBuffer != NULL )
					{
						vReleaseNetworkBufferAndDescriptor( pxNewBuffer );
					}
				}
			}
		}
#endif /* ipconfigUSE_LLMNR == 1 */
	}

	return ulIPAddress;
}

void harness()
{
  uint8_t buffer[10];
  TickType_t xIdentifier = 10;
  prvParseDNSReply(buffer, xIdentifier);
  return;
}

