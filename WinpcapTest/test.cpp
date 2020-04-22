#include <pcap.h>
#include <winsock.h>

#define ETH_ARP         0x0806  //��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
#define ARP_HARDWARE    1  //Ӳ�������ֶ�ֵΪ��ʾ��̫����ַ
#define ETH_IP          0x0800  //Э�������ֶα�ʾҪӳ���Э���ַ����ֵΪx0800��ʾIP��ַ
#define ARP_REQUEST     1   //ARP����
#define ARP_RESPONSE       2      //ARPӦ��
#pragma warning( disable : 4996 )

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
	int res;
	u_int netmask;	//��������
	char filter[] = "ethor proto \\arp"; //��һ��'\'Ϊת��,����arp���˹���
	bpf_program fcode;
	tm* ltime;
	char timestr[16];
	time_t local_tv_sec;
	pcap_pkthdr* header;
	const u_char* pkt_data;
	FILE* fp = fopen("ARP_log.txt", "w"); //��־��


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

	/*��װARP���ݰ����㲥����*/
	unsigned char sendbuf[42]; //arp���ṹ��С��42���ֽ�
	//���ñ�������mac��ַ��ip��ַ����Ҫ��ȷ���ã�����ѡ���������ƥ��
	//TODO �Զ����ѡ���������MAC��IP��ַ
	unsigned char src_mac[6] = { 0xf8,0x28,0x19,0xca,0x28,0x4f };
	unsigned char src_ip[4] = { 0xc0,0xa8,0x00,0x69 };
	unsigned char dest_mac[6] = { 0xff,0xff,0xff,0xff,0xff,0xff }; //MAC��ַ0xffffff��ʾ�㲥֡
	unsigned char dest_ip[4] = { 0xc0,0xa8,0x00,0x64 };
	EthernetHeader eh;
	ArpHeader ah;
	//��ֵMAC��ַ
	memcpy(eh.DestMAC, dest_mac, 6);   //��̫���ײ�Ŀ��MAC��ַ��ȫΪ�㲥��ַ
	memcpy(eh.SourMAC, src_mac, 6);   //��̫���ײ�ԴMAC��ַ
	memcpy(ah.smac, src_mac, 6);   //ARP�ֶ�ԴMAC��ַ
	memcpy(ah.dmac, dest_mac, 6);   //ARP�ֶ�Ŀ��MAC��ַ
	memcpy(ah.sip, src_ip, 4);   //ARP�ֶ�ԴIP��ַ
	//memset(ah.dip, 0x05, 4);   //ARP�ֶ�Ŀ��IP��ַ
	memcpy(ah.dip, dest_ip, 4);
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

	/*����ARP���ݰ���������¼��־*/
	netmask = ((sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	pcap_compile(adhandle, &fcode, filter, 1, netmask);	//���������
	pcap_setfilter(adhandle, &fcode);	//���ù�����

	/* �ͷ��豸�б� */
	pcap_freealldevs(alldevs);
	i = 0;

	//��ȡ���ݰ�������
	while (res = pcap_next_ex(adhandle, &header, &pkt_data) >= 0) {
		//��ʱ
		if (res == 0) {
			continue;
		}
		printf("message %d:\n", ++i);
		fprintf(fp, "message %d:\n", i);
		//���ñ�־�����յ�֮ǰ���͵�request��replyʱ��������
		bool ok = false;
		//����ARP����ARP����װ��MAC֡��MAC֡�ײ�ռ14�ֽ�
		ArpHeader* arpheader = (ArpHeader*)(pkt_data + 14);
		if (arpheader->op == 256) {
			printf("request message.\n");
			fprintf(fp, "request message.\n");
		} else {
			printf("reply message.\n");
			fprintf(fp, "reply message.\n");
			//�����ǰ����ʱreply���ģ���ͨ���Ƚ�ip���ж��Ƿ�ʱ֮ǰ���͵�request��Ӧ��reply
			if (memcmp(arpheader->dip, src_ip, sizeof(arpheader->dip)) == 0) {
				ok = true;
			}
		}
		printf("ARP packet length: %d\n", header->len);
		fprintf(fp, "ARP packet length: %d\n", header->len);
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
		printf("current time: %s\n", timestr);
		fprintf(fp, "current time: %s\n", timestr);
		//��ӡԴip
		printf("source ip: ");
		fprintf(fp, "source ip: ");
		for (int j = 0; j < 3; j++) {
			printf("%d.", arpheader->sip[j]);
			fprintf(fp, "%d.", arpheader->sip[j]);
		}
		printf("%d\n", arpheader->sip[3]);
		fprintf(fp, "%d\n", arpheader->sip[3]);
		//��ӡĿ��ip
		printf("destination ip: ");
		fprintf(fp, "destination ip: ");
		for (int j = 0; j < 3; j++) {
			printf("%d.", arpheader->dip[j]);
			fprintf(fp, "%d.", arpheader->dip[j]);
		}
		printf("%d\n", arpheader->dip[3]);
		fprintf(fp, "%d\n", arpheader->dip[3]);
		//��ӡԴmac
		printf("source mac: ");
		fprintf(fp, "source mac: ");
		for (int j = 0; j < 5; j++) {
			printf("%02x-", arpheader->smac[j]);
			fprintf(fp, "%02x-", arpheader->smac[j]);
		}
		printf("%x\n", arpheader->smac[5]);
		fprintf(fp, "%02x\n", arpheader->smac[5]);
		//��ӡĿ��mac
		printf("destination mac: ");
		fprintf(fp, "destination mac: ");
		for (int j = 0; j < 5; j++) {
			printf("%02x-", arpheader->dmac[j]);
			fprintf(fp, "%02x-", arpheader->dmac[j]);
		}
		printf("%x\n\n\n", arpheader->dmac[5]);
		fprintf(fp, "%x\n\n\n", arpheader->dmac[5]);
		fflush(fp);
		if (ok) {
			break;
		}
	}
	fclose(fp);
	return 0;
}
