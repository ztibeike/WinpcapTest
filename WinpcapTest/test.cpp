#include <pcap.h>
#include <winsock.h>

#define ETH_ARP         0x0806  //��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
#define ARP_HARDWARE    1  //Ӳ�������ֶ�ֵΪ��ʾ��̫����ַ
#define ETH_IP          0x0800  //Э�������ֶα�ʾҪӳ���Э���ַ����ֵΪx0800��ʾIP��ַ
#define ARP_REQUEST     1   //ARP����
#define ARP_RESPONSE       2      //ARPӦ��

//14�ֽ���̫���ײ�
struct EthernetHeader
{
	u_char DestMAC[6];    //Ŀ��MAC��ַ 6�ֽ�
	u_char SourMAC[6];   //ԴMAC��ַ 6�ֽ�
	u_short EthType;         //��һ��Э�����ͣ���0x0800������һ����IPЭ�飬0x0806Ϊarp  2�ֽ�
};

//28�ֽ�ARP֡�ṹ
struct ArpHeader
{
	unsigned short hdType;   //Ӳ������
	unsigned short proType;   //Э������
	unsigned char hdSize;   //Ӳ����ַ����
	unsigned char proSize;   //Э���ַ����
	unsigned short op;   //�������ͣ�ARP����1����ARPӦ��2����RARP����3����RARPӦ��4����
	u_char smac[6];   //ԴMAC��ַ
	u_char sip[4];   //ԴIP��ַ
	u_char dmac[6];   //Ŀ��MAC��ַ
	u_char dip[4];   //Ŀ��IP��ַ
};

//��������arp���İ����ܳ���42�ֽ�
struct ArpPacket {
	EthernetHeader ed;
	ArpHeader ah;
};


int main()
{
	pcap_if_t* alldevs;   //��������������
	pcap_if_t* d;   //ѡ�е����������� 
	int inum;   //ѡ������������
	int i = 0;   //forѭ������
	pcap_t* adhandle;   //����������������׽ʵ��,��pcap_open���صĶ���
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256

	/* ��ȡ�����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* ��ӡ�б� */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* ��ת��ѡ�е������� */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* ���豸 */
	if ((adhandle = pcap_open(d->name,          // �豸��
		65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		PCAP_OPENFLAG_PROMISCUOUS,    // ����ģʽ
		1000,             // ��ȡ��ʱʱ��
		NULL,             // Զ�̻�����֤
		errbuf            // ���󻺳��
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/*���ϴ�����WinPcap�����ĵ��ж������ҵ������ARP���Ĵ�����Ҫ�Լ���д*/

	//��ʼ���ARP�����������д���ڴ����У�������ʱ���ݿ�������д
	unsigned char sendbuf[42]; //arp���ṹ��С��42���ֽ�
	unsigned char mac[6] = { 0x00,0x11,0x22,0x33,0x44,0x55 };
	unsigned char ip[4] = { 0x01,0x02,0x03,0x04 };
	EthernetHeader eh;
	ArpHeader ah;
	//��ֵMAC��ַ
	memset(eh.DestMAC, 0xff, 6);   //��̫���ײ�Ŀ��MAC��ַ��ȫΪ�㲥��ַ
	memcpy(eh.SourMAC, mac, 6);   //��̫���ײ�ԴMAC��ַ
	memcpy(ah.smac, mac, 6);   //ARP�ֶ�ԴMAC��ַ
	memset(ah.dmac, 0xff, 6);   //ARP�ֶ�Ŀ��MAC��ַ
	memcpy(ah.sip, ip, 4);   //ARP�ֶ�ԴIP��ַ
	memset(ah.dip, 0x05, 4);   //ARP�ֶ�Ŀ��IP��ַ
	eh.EthType = htons(ETH_ARP);   //htons�����������޷��Ŷ�������ת���������ֽ�˳��
	ah.hdType = htons(ARP_HARDWARE);
	ah.proType = htons(ETH_IP);
	ah.hdSize = 6;
	ah.proSize = 4;
	ah.op = htons(ARP_REQUEST);

	//����һ��ARP����
	memset(sendbuf, 0, sizeof(sendbuf));   //ARP����
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
	//������ͳɹ�
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
		printf("\nPacketSend succeed\n");
	}
	else {
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
	}

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);

	return 0;
}
