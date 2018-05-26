#define BIND_RX 			"00000001"
#define BIND_RX_RESP 			"80000001"
#define BIND_TX 			"00000002"
#define BIND_TX_RESP 			"80000002"
#define BIND_TRX 			"00000009"
#define BIND_TRX_RESP 			"80000009"
#define SUBMIT_SM 			"00000004"
#define SUBMIT_SM_RESP 			"80000004"
#define DELIVER_SM 			"00000005"
#define DELIVER_SM_RESP 		"80000005"
#define ENQUIRE_LINK 			"00000015"
#define ENQUIRE_LINK_RESP 		"80000015"

#define SMPP_TLV_MESSAGE_PAYLOAD	0X0424
#define SMPP_TLV_SAR_MSG_REF_NUM	0X020C
#define SMPP_TLV_SAR_TOTAL_SEGMENTS	0X020E
#define SMPP_TLV_SAR_SEGMENT_SEQNUM	0X020F
#define SMPP_TLV_RECEIPTED_MESSAGE_ID	0X001E
#define SMPP_TLV_MESSAGE_STATE		0X0427
#define SMPP_TLV_SOURCE_NETWORK_TYPE	0X000E
#define SMPP_TLV_DEST_NETWORK_TYPE	0X0006
#define SMPP_TLV_SOURCE_PORT  		0X020A
#define SMPP_TLV_DEST_PORT    		0X020B

typedef struct PDU
{
        int command_length;
        int command_id;
        int command_status;
        int sequence;
        char system_id[16];
        char password[9];
        char system_type[13];
        int interface_version;
        int addr_ton;
        int addr_npi;
        char address_range[41];
        char service_type[6];
	int source_addr_ton;
	int source_addr_npi;
	char source_addr[21];
	int dest_addr_ton;
	int dest_addr_npi;
	char dest_addr[21];
	int esm_class;
	int protocol_id;
	int priority_flag;
	char schedule_delivery_time[17];
	char validity_period[17];
	int registered_delivery;
	int replace_if_present_flag;
	int data_coding;
	int sm_default_msg_id;
	int sm_length;
	char short_message[254];
	char message_id[65];
}PDU;
