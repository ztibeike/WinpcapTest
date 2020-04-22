#include <pcap.h>
#include <winsock.h>

#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1   //ARP请求
#define ARP_RESPONSE       2      //ARP应答
#pragma warning( disable : 4996 )

//14字节以太网首部
struct EthernetHeader
{
	u_char DestMAC[6];    //目的MAC地址 6字节
	u_char SourMAC[6];   //源MAC地址 6字节
	u_short EthType;         //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

//28字节ARP帧结构
struct ArpHeader
{
	unsigned short hdType;   //硬件类型
	unsigned short proType;   //协议类型
	unsigned char hdSize;   //硬件地址长度
	unsigned char proSize;   //协议地址长度
	unsigned short op;   //操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
	u_char smac[6];   //源MAC地址
	u_char sip[4];   //源IP地址
	u_char dmac[6];   //目的MAC地址
	u_char dip[4];   //目的IP地址
};

//定义整个arp报文包，总长度42字节
struct ArpPacket {
	EthernetHeader ed;
	ArpHeader ah;
};


int main()
{
	pcap_if_t* alldevs;   //所有网络适配器
	pcap_if_t* d;   //选中的网络适配器 
	int inum;   //选择网络适配器
	int i = 0;   //for循环变量
	pcap_t* adhandle;   //打开网络适配器，捕捉实例,是pcap_open返回的对象
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
	int res;
	u_int netmask;	//子网掩码
	char filter[] = "ethor proto \\arp"; //第一个'\'为转义,设置arp过滤规则
	bpf_program fcode;
	tm* ltime;
	char timestr[16];
	time_t local_tv_sec;
	pcap_pkthdr* header;
	const u_char* pkt_data;
	FILE* fp = fopen("ARP_log.txt", "w"); //日志流


	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
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
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name,          // 设备名
		65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/*封装ARP数据包并广播发送*/
	unsigned char sendbuf[42]; //arp包结构大小，42个字节
	//设置本机网卡mac地址和ip地址，需要正确设置，且与选择的网卡所匹配
	//TODO 自动获得选择的网卡的MAC和IP地址
	unsigned char src_mac[6] = { 0xf8,0x28,0x19,0xca,0x28,0x4f };
	unsigned char src_ip[4] = { 0xc0,0xa8,0x00,0x69 };
	unsigned char dest_mac[6] = { 0xff,0xff,0xff,0xff,0xff,0xff }; //MAC地址0xffffff表示广播帧
	unsigned char dest_ip[4] = { 0xc0,0xa8,0x00,0x64 };
	EthernetHeader eh;
	ArpHeader ah;
	//赋值MAC地址
	memcpy(eh.DestMAC, dest_mac, 6);   //以太网首部目的MAC地址，全为广播地址
	memcpy(eh.SourMAC, src_mac, 6);   //以太网首部源MAC地址
	memcpy(ah.smac, src_mac, 6);   //ARP字段源MAC地址
	memcpy(ah.dmac, dest_mac, 6);   //ARP字段目的MAC地址
	memcpy(ah.sip, src_ip, 4);   //ARP字段源IP地址
	//memset(ah.dip, 0x05, 4);   //ARP字段目的IP地址
	memcpy(ah.dip, dest_ip, 4);
	eh.EthType = htons(ETH_ARP);   //htons：将主机的无符号短整形数转换成网络字节顺序
	ah.hdType = htons(ARP_HARDWARE);
	ah.proType = htons(ETH_IP);
	ah.hdSize = 6;
	ah.proSize = 4;
	ah.op = htons(ARP_REQUEST);

	//构造一个ARP请求
	memset(sendbuf, 0, sizeof(sendbuf));   //ARP清零
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
	//如果发送成功
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
		printf("\nPacketSend succeed\n");
	}
	else {
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
	}

	/*捕获ARP数据包解析并记录日志*/
	netmask = ((sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	pcap_compile(adhandle, &fcode, filter, 1, netmask);	//编译过滤器
	pcap_setfilter(adhandle, &fcode);	//设置过滤器

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);
	i = 0;

	//获取数据包并解析
	while (res = pcap_next_ex(adhandle, &header, &pkt_data) >= 0) {
		//超时
		if (res == 0) {
			continue;
		}
		printf("message %d:\n", ++i);
		fprintf(fp, "message %d:\n", i);
		//设置标志，当收到之前发送的request的reply时结束捕获
		bool ok = false;
		//解析ARP包，ARP包封装在MAC帧，MAC帧首部占14字节
		ArpHeader* arpheader = (ArpHeader*)(pkt_data + 14);
		if (arpheader->op == 256) {
			printf("request message.\n");
			fprintf(fp, "request message.\n");
		} else {
			printf("reply message.\n");
			fprintf(fp, "reply message.\n");
			//如果当前报文时reply报文，则通过比较ip来判断是否时之前发送的request对应的reply
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
		//打印源ip
		printf("source ip: ");
		fprintf(fp, "source ip: ");
		for (int j = 0; j < 3; j++) {
			printf("%d.", arpheader->sip[j]);
			fprintf(fp, "%d.", arpheader->sip[j]);
		}
		printf("%d\n", arpheader->sip[3]);
		fprintf(fp, "%d\n", arpheader->sip[3]);
		//打印目的ip
		printf("destination ip: ");
		fprintf(fp, "destination ip: ");
		for (int j = 0; j < 3; j++) {
			printf("%d.", arpheader->dip[j]);
			fprintf(fp, "%d.", arpheader->dip[j]);
		}
		printf("%d\n", arpheader->dip[3]);
		fprintf(fp, "%d\n", arpheader->dip[3]);
		//打印源mac
		printf("source mac: ");
		fprintf(fp, "source mac: ");
		for (int j = 0; j < 5; j++) {
			printf("%02x-", arpheader->smac[j]);
			fprintf(fp, "%02x-", arpheader->smac[j]);
		}
		printf("%x\n", arpheader->smac[5]);
		fprintf(fp, "%02x\n", arpheader->smac[5]);
		//打印目的mac
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
