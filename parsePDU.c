#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include"smpp.h"

unsigned char *TrimPDUSpecialChars(unsigned char *pdu)
{
	unsigned char *buf;	
	int i,j,flag;
	buf = malloc(sizeof(unsigned char *)*1024);
	for(i=0,j=0,flag=1;i<strlen(pdu);i++)
        {
                if(isalnum(pdu[i]))
                {
                        if(isdigit(pdu[i]))
			{
                                buf[j++] = pdu[i];
				flag++;
			}
                        else if(flag%2 == 0)
			{
                                buf[j++] = pdu[i];
				flag++;
			}
                }
        }
	//printf("2.PDU : %s\n",buf);
	return buf;
}

unsigned char *TrimPDUSpace(unsigned char *src)
{
	unsigned char *buf;	
	int i,j;
	buf = malloc(sizeof(unsigned char *)*1024);
	for(i=0,j=0;i<strlen(src);i++)
	{
		if(src[i] != 32)
			buf[j++] = src[i];
	}
	//printf("1.PDU : %s\n",buf);
	return buf;
}

unsigned char *CheckError(char *errStr)
{
	unsigned int decErr = 0;
        sscanf(errStr, "%X", &decErr);
	if(decErr == 1)
		return "Message Length is invalid";
	else if(decErr == 2)
		return "Command Length is invalid";
	else if(decErr == 3)
		return "Invalid Command ID";
	else if(decErr == 4)
		return "Incorrect BIND Status for given command";
	else if(decErr == 5)
		return "ESME Already in Bound State";
	else if(decErr == 6)
		return "Invalid Priority Flag";
	else if(decErr == 7)
		return "Invalid Registered Delivery Flag";
	else if(decErr == 8)
		return "System Error";
	else if(decErr == 9)
		return "Reserved";
	else if(decErr == 10)
		return "Invalid Source Address";
	else if(decErr == 11)
		return "Invalid Dest Addr";
	else if(decErr == 12)
		return "Message ID is invalid";
	else if(decErr == 13)
		return "Bind Failed";
	else if(decErr == 14)
		return "Invalid Password";
	else if(decErr == 15)
		return "Invalid System ID";
	else if(decErr == 16)
		return "Reserved";
	else if(decErr == 17)
		return "Cancel SM Failed";
	else if(decErr == 18)
		return "Reserved";
	else if(decErr == 19)
		return "Replace SM Failed";
	else if(decErr == 20)
		return "Message Queue Full";
	else if(decErr == 21)
		return "Invalid Service Type";
	else if(decErr >= 22 && decErr <= 50)
		return "Reserved";
	else if(decErr == 51)
		return "Invalid number of destinations";
	else if(decErr == 52)
		return "Invalid Distribution List name";
	else if(decErr >= 53 && decErr <= 63)
		return "Reserved";
	else if(decErr == 64)
		return "Destination flag is invalid(submit_multi)";
	else if(decErr == 65)
		return "Reserved";
	else if(decErr == 66)
		return "Invalid .submit with replace. request(i.e. submit_sm withreplace_if_present_flag set)";
	else if(decErr == 67)
		return "Invalid esm_class field data";
	else if(decErr == 68)
		return "Cannot Submit to Distribution List";
	else if(decErr == 69)
		return "submit_sm or submit_multi failed";
	else if(decErr >= 70 && decErr <= 71)
		return "Reserved";
	else if(decErr == 72)
		return "Invalid Source address TON";
	else if(decErr == 73)
		return "Invalid Source address NPI";
	else if(decErr == 80)
		return "Invalid Destination address TON";
	else if(decErr == 81)
		return "Invalid Destination address NPI";
	else if(decErr == 82)
		return "Reserved";
	else if(decErr == 83)
		return "Invalid system_type field";
	else if(decErr == 84)
		return "Invalid replace_if_present flag";
	else if(decErr == 85)
		return "Invalid number of messages";
	else if(decErr >= 86 && decErr <= 87)
		return "Reserved";
	else if(decErr == 88)
		return "Throttling error (ESME has exceeded allowed message limits)";
	else if(decErr >= 89 && decErr <= 96)
		return "Reserved";
	else if(decErr == 97)
		return "Invalid Scheduled Delivery Time";
	else if(decErr == 98)
		return "Invalid message validity period(Expiry time)";
	else if(decErr == 99)
		return "Predefined Message Invalid or Not Found";
	else if(decErr == 100)
		return "ESME Receiver Temporary App Error Code";
	else if(decErr == 101)
		return "ESME Receiver Permanent App Error Code";
	else if(decErr == 102)
		return "ESME Receiver Reject Message Error Code";
	else if(decErr == 103)
		return "query_sm request failed";
	else if(decErr >= 104 && decErr <= 191)
		return "Reserved";
	else if(decErr == 192)
		return "Error in the optional part of the PDU Body.";
	else if(decErr == 193)
		return "Optional Parameter not allowed";
	else if(decErr == 194)
		return "Invalid Parameter Length.";
	else if(decErr == 195)
		return "Expected Optional Parameter missing";
	else if(decErr == 196)
		return "Invalid Optional Parameter Value";
	else if(decErr >= 197 && decErr <= 253)
		return "Reserved";
	else if(decErr == 254)
		return "Delivery Failure (used for data_sm_resp)";
	else if(decErr == 255)
		return "Unknown Error";
	else if(decErr >= 256 && decErr <= 1023)
		return "Reserved for SMPP extension";
	else if(decErr >= 1024 && decErr <= 1279)
		return "Reserved for SMSC vendor specific errors";
	else if(decErr >= 1280)
		return "Reserved";
}

void ParsePDU(unsigned char *pdu)
{
	int i,j,dec,len,sm_len,flag,dcs,DC;
	char temp[9],ch[3];
	for(i=16,j=0;i<24;i++)
	{
		temp[j++] = pdu[i];
	}
	temp[j] = '\0';
	if(strcmp(temp, "00000000"))
		printf("\n[ERROR] Command Status: 0x%s -> %s\n", temp, CheckError(temp));
	strcpy(temp, "");
	for(i=8,j=0;i<16;i++)
                temp[j++] = pdu[i];
	printf("\n==================================================");
	if(strcmp(temp, BIND_RX) == 0)
	{
		printf("\n\t\t-:: BIND RX ::-");
		printf("\n==================================================");
		printf("\nCommand Length \t\t\t: ");
		for(i=0;i<8;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Id \t\t\t: ");
		for(;i<16;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Status \t\t\t: ");
		for(;i<24;i++)
			printf("%c", pdu[i]);
		printf("\nSequence \t\t\t: ");
		for(;i<32;i++)
			printf("%c", pdu[i]);
		printf("\nSystem Id \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
		i += 2;
		printf("\nPassword \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
		i += 2;
		printf("\nSystem Type \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
		i += 2;
		printf("\nInterface Version \t\t: %c%c", pdu[i], pdu[i+1]);
		i += 2;
		printf("\nADDR TON \t\t\t: %c%c", pdu[i], pdu[i+1]);
		i += 2;
		printf("\nADDR NPI \t\t\t: %c%c", pdu[i], pdu[i+1]);
		i += 2;
		printf("\nAddress Range \t\t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(pdu[i]!=51)
				printf("%c", pdu[i]);
		}
	}
	else if(strcmp(temp, BIND_RX_RESP) == 0)
	{
		printf("\n\t\t-:: BIND RX RESP ::-");
		printf("\n==================================================");
		printf("\nCommand Length \t\t\t: ");
		for(i=0;i<8;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Id \t\t\t: ");
		for(;i<16;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Status \t\t\t: ");
		for(;i<24;i++)
			printf("%c", pdu[i]);
		printf("\nSequence \t\t\t: ");
		for(;i<32;i++)
			printf("%c", pdu[i]);
		printf("\nSystem Id \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
	}
	else if(strcmp(temp, BIND_TX) == 0)
	{
		printf("\n\t\t-:: BIND TX ::-");
		printf("\n==================================================");
		printf("\nCommand Length \t\t\t: ");
		for(i=0;i<8;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Id \t\t\t: ");
		for(;i<16;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Status \t\t\t: ");
		for(;i<24;i++)
			printf("%c", pdu[i]);
		printf("\nSequence \t\t\t: ");
		for(;i<32;i++)
			printf("%c", pdu[i]);
		printf("\nSystem Id \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
		i += 2;
		printf("\nPassword \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
		i += 2;
		printf("\nSystem Type \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
		i += 2;
		printf("\nInterface Version \t\t: %c%c", pdu[i], pdu[i+1]);
		i += 2;
		printf("\nADDR TON \t\t\t: %c%c", pdu[i], pdu[i+1]);
		i += 2;
		printf("\nADDR NPI \t\t\t: %c%c", pdu[i], pdu[i+1]);
		i += 2;
		printf("\nAddress Range \t\t\t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(pdu[i]!=51)
				printf("%c", pdu[i]);
		}
	}
	else if(strcmp(temp, BIND_TX_RESP) == 0)
	{
		printf("\n\t\t-:: BIND RX RESP ::-");
		printf("\n==================================================");
		printf("\nCommand Length \t\t\t: ");
		for(i=0;i<8;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Id \t\t\t: ");
		for(;i<16;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Status \t\t\t: ");
		for(;i<24;i++)
			printf("%c", pdu[i]);
		printf("\nSequence \t\t\t: ");
		for(;i<32;i++)
			printf("%c", pdu[i]);
		printf("\nSystem Id \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
	}
	else if(strcmp(temp, BIND_TRX) == 0)
	{
		printf("\n\t\t-:: BIND TRX ::-");
		printf("\n==================================================");
		printf("\nCommand Length \t\t\t: ");
		for(i=0;i<8;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Id \t\t\t: ");
		for(;i<16;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Status \t\t\t: ");
		for(;i<24;i++)
			printf("%c", pdu[i]);
		printf("\nSequence \t\t\t: ");
		for(;i<32;i++)
			printf("%c", pdu[i]);
		printf("\nSystem Id \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
		i += 2;
		printf("\nPassword \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
		i += 2;
		printf("\nSystem Type \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
		i += 2;
		printf("\nInterface Version \t\t: %c%c", pdu[i], pdu[i+1]);
		i += 2;
		printf("\nADDR TON \t\t\t: %c%c", pdu[i], pdu[i+1]);
		i += 2;
		printf("\nADDR NPI \t\t\t: %c%c", pdu[i], pdu[i+1]);
		i += 2;
		printf("\nAddress Range \t\t\t: ");
		for(;;i++)
                {
                        if(pdu[i] == 48 && pdu[i+1] == 48)
                                break;
                        if(pdu[i] != 51)
                                printf("%c", pdu[i]);
                }
	}
	else if(strcmp(temp, BIND_TRX_RESP) == 0)
	{
		printf("\n\t\t-:: BIND TRX RESP ::-");
		printf("\n==================================================");
		printf("\nCommand Length \t\t\t: ");
		for(i=0;i<8;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Id \t\t\t: ");
		for(;i<16;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Status \t\t\t: ");
		for(;i<24;i++)
			printf("%c", pdu[i]);
		printf("\nSequence \t\t\t: ");
		for(;i<32;i++)
			printf("%c", pdu[i]);
		printf("\nSystem Id \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
			{
				sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
				sscanf(ch, "%X", &dec);
				printf("%c", dec);
				flag = 0;
			}
			flag++;
		}
	}
	else if(strcmp(temp, SUBMIT_SM) == 0)
	{
		printf("\n\t\t-:: SUBMIT SM ::-");
		printf("\n==================================================");
		printf("\nCommand Length \t\t\t: ");
		for(i=0;i<8;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Id \t\t\t: ");
		for(;i<16;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Status \t\t\t: ");
		for(;i<24;i++)
			printf("%c", pdu[i]);
		printf("\nSequence \t\t\t: ");
		for(;i<32;i++)
			printf("%c", pdu[i]);
		printf("\nService Type \t\t\t: ");
		flag = 1;
		for(;;i++)
		{
			if(flag == 1 && pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
                        {
                        	sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
                                sscanf(ch, "%X", &dec);
                                printf("%c", dec);
                                flag = 0;
                        }
                        flag++;
		}
		i += 2;
		printf("\nSrc Addr TON \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		i += 2;
		printf("\nSrc Addr NPI \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		i += 2;
		printf("\nSource Address \t\t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			/*if(pdu[i] != 51)
				printf("%c", pdu[i]);*/
			//printf("%c ", pdu[i]);
			sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
			sscanf(ch, "%d", &dec);
			printf("%d",dec-30);
			i++;
		}
		i += 2;
		printf("\nDest Addr TON \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		i += 2;
		printf("\nDest Addr NPI \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		i += 2;
		printf("\nDest Address \t\t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			/*if(pdu[i] != 51)
				printf("%c", pdu[i]);*/
			sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
			sscanf(ch, "%d", &dec);
			printf("%d",dec-30);
			i++;
		}
		i += 2;
		printf("\nESM Class \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		i += 2;
		printf("\nProtocol Id \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		i += 2;
		printf("\nPriority Flag \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		i += 2;
		printf("\nSchd delv time \t\t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			printf("%c", pdu[i]);
		}
		i += 2;
		printf("\nValidity period \t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			printf("%c", pdu[i]);
		}
		i += 2;
		printf("\nRegd delivery \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		i += 2;
		printf("\nReplace Flag \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		i += 2;
		printf("\nData coding \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		dcs = pdu[i+1]-48;
		i += 2;
		printf("\nsm default msg Id \t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		i += 2;
		printf("\nsm length \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
		sscanf(ch, "%X", &sm_len);
		printf("%d", sm_len);
		i += 2;
		printf("\nShort Message \t\t\t: ");
		len = i+(sm_len*2);
		flag = 1;
		for(;i<len;i++)
		{
			if(dcs == 0 || dcs == 3)
			{
				if(flag == 1 && pdu[i] == 48 && pdu[i+1] == 48)
					break;
				if(flag == 2)
				{
					sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
					sscanf(ch, "%X", &dec);
					printf("%c", dec);
					flag = 0;
				}
				flag++;
			}
			else
			{
				printf("%c", pdu[i]);
			}
		}
		if(sm_len == 0)
                {
                	printf("\n--------------------------------------------------");
			for(;i<strlen(pdu);i++)
                        {
                                sprintf(ch, "%c%c%c%c", pdu[i], pdu[i+1], pdu[i+2], pdu[i+3]);
                                sscanf(ch, "%X", &dec);
                                if(dec == SMPP_TLV_SOURCE_NETWORK_TYPE)
                                {
//printf(" TAG-%d",dec);
                                        i+=6;
                                        sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                        sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
                                        i+=1;
                                        printf("\nSMPP_TLV_SOURCE_NETWORK_TYPE \t: ");
                                        for(j=0;j<dec;j++)
                                                printf("%c", pdu[i++]);
                                }
                                else if(dec == SMPP_TLV_DEST_NETWORK_TYPE)
                                {
//printf(" TAG-%d",dec);
                                        i+=6;
                                        sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                        sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
                                        i+=1;
                                        printf("\nSMPP_TLV_DEST_NETWORK_TYPE \t: ");
                                        for(j=0;j<dec;j++)
                                                printf("%c", pdu[i++]);
                                }
                                else if(dec == SMPP_TLV_SOURCE_PORT)
                                {
//printf(" TAG-%d",dec);
                                        i+=6;
                                        sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                        sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
                                        i+=2;
                                        printf("\nSMPP_TLV_SOURCE_PORT \t\t: ");
                                        for(j=0;j<dec+2;j++)
                                                printf("%c", pdu[i++]);
                                        i--;
                                }
                                else if(dec == SMPP_TLV_DEST_PORT)
                                {
//printf(" TAG-%d",dec);
                                        i+=6;
                                        sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                        sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
                                        i+=2;
                                        printf("\nSMPP_TLV_DEST_PORT \t\t: ");
                                        for(j=0;j<dec+2;j++)
                                                printf("%c", pdu[i++]);
                                        i--;
                                }
                                else if(dec == SMPP_TLV_SAR_MSG_REF_NUM)
                                {
//printf(" TAG-%d",dec);
                                        i+=6;
                                        sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                        sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
                                        i+=2;
                                        printf("\nSMPP_TLV_SAR_MSG_REF_NUM \t: ");
                                        for(j=0;j<dec+2;j++)
                                                printf("%c", pdu[i++]);
                                        i--;
                                }
                                else if(dec == SMPP_TLV_SAR_TOTAL_SEGMENTS)
                                {
//printf(" TAG-%d",dec);
                                        i+=6;
                                        sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                        sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
                                        i+=2;
                                        printf("\nSMPP_TLV_SAR_TOTAL_SEGMENTS \t: ");
                                        sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                        sscanf(ch, "%X", &dec);
                                        printf("%d", dec);
                                }
                                else if(dec == SMPP_TLV_SAR_SEGMENT_SEQNUM)
                                {
//printf(" TAG-%d",dec);
                                        i+=6;
                                        sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                        sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
                                        i+=2;
                                        printf("\nSMPP_TLV_SAR_SEGMENT_SEQNUM \t: ");
                                        sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                        sscanf(ch, "%X", &dec);
                                        printf("%d", dec);
                                }
                                else if(dec == SMPP_TLV_MESSAGE_PAYLOAD)
                                {
//printf(" TAG-%d",dec);
                                        i+=6;
                                        sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                        sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
                                        i+=2;
                                        printf("\nSMPP_TLV_MESSAGE_PAYLOAD \t: ");
                                        for(j=0;j<dec;j++)
					{
						if(dcs == 0 || dcs == 3)
						{
                                			sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                			sscanf(ch, "%X", &DC);
                                			printf("%c", DC);
							i+=2;
						}
						else
						{
							printf("%c", pdu[i++]);
						}
					}
                                }
			}
                }
	}
	else if(strcmp(temp, SUBMIT_SM_RESP) == 0)
	{
		printf("\n\t\t-:: SUBMIT SM RESP ::-");
		printf("\n==================================================");
		printf("\nCommand Length \t\t\t: ");
		for(i=0;i<8;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Id \t\t\t: ");
		for(;i<16;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Status \t\t\t: ");
		for(;i<24;i++)
			printf("%c", pdu[i]);
		printf("\nSequence \t\t\t: ");
		for(;i<32;i++)
			printf("%c", pdu[i]);
		printf("\nMessage Id \t\t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			printf("%c", pdu[i]);
		}
	}
	else if(strcmp(temp, DELIVER_SM) == 0)
	{
		printf("\n\t\t-:: DELIVER SM ::-");
		printf("\n==================================================");
		printf("\nCommand Length \t\t\t: ");
		for(i=0;i<8;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Id \t\t\t: ");
		for(;i<16;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Status \t\t\t: ");
		for(;i<24;i++)
			printf("%c", pdu[i]);
		printf("\nSequence \t\t\t: ");
		for(;i<32;i++)
			printf("%c", pdu[i]);
		printf("\nService Type \t\t\t: ");
		for(;;i++)
		{
			if(flag == 1 && pdu[i] == 48 && pdu[i+1] == 48)
				break;
			if(flag == 2)
                        {
                        	sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
                                sscanf(ch, "%X", &dec);
                                printf("%c", dec);
                                flag = 0;
                        }
                        flag++;
		}
                i += 2;
                printf("\nSrc Addr TON \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
                i += 2;
                printf("\nSrc Addr NPI \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
                i += 2;
                printf("\nSource Address \t\t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			/*if(pdu[i] != 51)
				printf("%c", pdu[i]);*/
			sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
			sscanf(ch, "%d", &dec);
			printf("%d",dec-30);
			i++;
		}
                i += 2;
                printf("\nDest Addr TON \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
                i += 2;
                printf("\nDest Addr NPI \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
                i += 2;
                printf("\nDest Address \t\t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			/*if(pdu[i] != 51)
				printf("%c", pdu[i]);*/
			sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
			sscanf(ch, "%d", &dec);
			printf("%d",dec-30);
			i++;
		}
                i += 2;
                printf("\nESM Class \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
                i += 2;
                printf("\nProtocol Id \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
                i += 2;
                printf("\nPriority Flag \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
                i += 2;
                printf("\nSchd delv time \t\t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			printf("%c", pdu[i]);
		}
                i += 2;
                printf("\nValidity period \t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			printf("%c", pdu[i]);
		}
                i += 2;
                printf("\nRegd delivery \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
                i += 2;
                printf("\nReplace Flag \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
                i += 2;
                printf("\nData coding \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
		dcs = pdu[i+1]-48;
                i += 2;
                printf("\nsm default msg Id \t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                sscanf(ch, "%X", &dec);
                printf("%d", dec);
                i += 2;
		printf("\nsm length \t\t\t: ");
		sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
		sscanf(ch, "%X", &dec);
		printf("%d", dec);
                i += 2;
                printf("\nShort Message \t\t\t: ");
		len = i+(dec*2);
		flag = 1;
                for(;i<len;i++)
                {
			if(dcs == 0 || dcs == 3)
                        {
	                        if(pdu[i] == 48 && pdu[i+1] == 48)
        	                        break;
                	        if(flag == 2)
                        	{
                                	sprintf(ch, "%c%c", pdu[i-1], pdu[i]);
                                	sscanf(ch, "%X", &dec);
                                	printf("%c", dec);
                                	flag = 0;
                        	}
                        	flag++;
			}
                        else
                        {
                                printf("%c", pdu[i]);
                        }
                }
		if(dec == 0)
		{
                	printf("\n--------------------------------------------------");
			for(;i<strlen(pdu);i++)
			{
				sprintf(ch, "%c%c%c%c", pdu[i], pdu[i+1], pdu[i+2], pdu[i+3]);
                		sscanf(ch, "%X", &dec);
				if(dec == SMPP_TLV_SOURCE_NETWORK_TYPE)
				{
//printf(" TAG-%d",dec);
					i+=6;
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
					i+=1;
					printf("\nSMPP_TLV_SOURCE_NETWORK_TYPE \t: ");
					for(j=0;j<dec;j++)
						printf("%c", pdu[i++]);
				}
				else if(dec == SMPP_TLV_DEST_NETWORK_TYPE)
				{
//printf(" TAG-%d",dec);
					i+=6;
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
					i+=1;
					printf("\nSMPP_TLV_DEST_NETWORK_TYPE \t: ");
					for(j=0;j<dec;j++)
						printf("%c", pdu[i++]);
				}
				else if(dec == SMPP_TLV_RECEIPTED_MESSAGE_ID)
				{
//printf(" TAG-%d",dec);
					i+=6;
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
					i+=1;
					printf("\nSMPP_TLV_RECEIPTED_MESSAGE_ID \t: ");
					for(j=0;j<dec;j++)
						printf("%c", pdu[i++]);
				}
				else if(dec == SMPP_TLV_MESSAGE_STATE)
				{
//printf(" TAG-%d",dec);
					i+=6;
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
					i+=1;
					printf("\nSMPP_TLV_MESSAGE_STATE \t\t: ");
					for(j=0;j<dec;j++)
						printf("%c", pdu[i++]);
				}
				else if(dec == SMPP_TLV_SAR_MSG_REF_NUM)
				{
//printf(" TAG-%d",dec);
					i+=6;
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
					i+=2;
					printf("\nSMPP_TLV_SAR_MSG_REF_NUM \t: ");
					for(j=0;j<dec+2;j++)
						printf("%c", pdu[i++]);
					i--;
				}
				else if(dec == SMPP_TLV_SAR_TOTAL_SEGMENTS)
				{
//printf(" TAG-%d",dec);
					i+=6;
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
					i+=2;
					printf("\nSMPP_TLV_SAR_TOTAL_SEGMENTS \t: ");
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
					printf("%d", dec);
				}
				else if(dec == SMPP_TLV_SAR_SEGMENT_SEQNUM)
				{
//printf(" TAG-%d",dec);
					i+=6;
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
					i+=2;
					printf("\nSMPP_TLV_SAR_SEGMENT_SEQNUM \t: ");
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
					printf("%d", dec);
				}
				else if(dec == SMPP_TLV_MESSAGE_PAYLOAD)
				{
//printf(" TAG-%d",dec);
					i+=6;
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
//printf(" LEN-%d",dec);
					i+=2;
					printf("\nSMPP_TLV_MESSAGE_PAYLOAD \t: ");
					for(j=0;j<dec;j++)
					{
						if(dcs == 0 || dcs == 3)
						{
                                			sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                                			sscanf(ch, "%X", &DC);
                                			printf("%c", DC);
							i+=2;
						}
						else
						{
							printf("%c", pdu[i++]);
						}
					}
				}
				else
				{
printf(" TAG-%d",dec);
					i+=6;
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
printf(" LEN-%d",dec);
					i+=2;
					printf("\nInvalid TLV!!! \t: ");
					sprintf(ch, "%c%c", pdu[i], pdu[i+1]);
                			sscanf(ch, "%X", &dec);
					printf("%d", dec);
				}
			}
		}
	}
	else if(strcmp(temp, DELIVER_SM_RESP) == 0)
	{
		printf("\n\t\t-:: DELIVER SM RESP ::-");
		printf("\n==================================================");
		printf("\nCommand Length \t\t\t: ");
		for(i=0;i<8;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Id \t\t\t: ");
		for(;i<16;i++)
			printf("%c", pdu[i]);
		printf("\nCommand Status \t\t\t: ");
		for(;i<24;i++)
			printf("%c", pdu[i]);
		printf("\nSequence \t\t\t: ");
		for(;i<32;i++)
			printf("%c", pdu[i]);
		printf("\nMessage Id \t\t\t: ");
		for(;;i++)
		{
			if(pdu[i] == 48 && pdu[i+1] == 48)
				break;
			printf("%c", pdu[i]);
		}
	}
	else if(strcmp(temp, ENQUIRE_LINK) == 0)
        {
                printf("\n\t\t-:: ENQUIRE LINK ::-");
                printf("\n==================================================");
                printf("\nCommand Length \t\t\t: ");
                for(i=0;i<8;i++)
                        printf("%c", pdu[i]);
                printf("\nCommand Id \t\t\t: ");
                for(;i<16;i++)
                        printf("%c", pdu[i]);
                printf("\nCommand Status \t\t\t: ");
                for(;i<24;i++)
                        printf("%c", pdu[i]);
                printf("\nSequence \t\t\t: ");
                for(;i<32;i++)
                        printf("%c", pdu[i]);
        }
	else if(strcmp(temp, ENQUIRE_LINK_RESP) == 0)
        {
                printf("\n\t\t-:: ENQUIRE LINK RESP ::-");
                printf("\n==================================================");
                printf("\nCommand Length \t\t\t: ");
                for(i=0;i<8;i++)
                        printf("%c", pdu[i]);
                printf("\nCommand Id \t\t\t: ");
                for(;i<16;i++)
                        printf("%c", pdu[i]);
                printf("\nCommand Status \t\t\t: ");
                for(;i<24;i++)
                        printf("%c", pdu[i]);
                printf("\nSequence \t\t\t: ");
                for(;i<32;i++)
                        printf("%c", pdu[i]);
        }
	printf("\n==================================================\n\n");
}

int main(int argc, char **argv)
{
	unsigned char *pdu;
	if(argc != 2)
	{
		printf("\n********** [USAGE : %s \"<HEX PDU DUMP>\"] **********\n\n", argv[0]);
		exit(1);
	}
	pdu = TrimPDUSpace(argv[1]);
	//pdu = TrimPDUSpecialChars(pdu);
	ParsePDU(pdu);
	free(pdu);
	return 0;
}
