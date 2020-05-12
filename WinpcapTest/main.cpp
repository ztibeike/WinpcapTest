#include <pcap.h>
#include <winsock.h>

#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define REQUEST     1   //ARP请求
#define RESPONSE       2      //ARP应答
#define IPTOSBUFFERS    12
#define IPADDR	1	//自定义常量：IP地址
#define MACADDR	2	//自定义常量：MAC地址
#define MAXNUM 10	//自定义常量：最大网络设备数量
#pragma warning( disable : 4996 )


//14字节以太网首部
struct EthHeader
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
	EthHeader ed;
	ArpHeader ah;
};


pcap_if_t* alldevs;   //所有网络适配器
pcap_if_t* d;   //选中的网络适配器 
int inum;   //选择网络适配器
int i = 0;   //for循环变量
pcap_t* adhandle;   //打开网络适配器，捕捉实例,是pcap_open返回的对象
char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
char filter[] = "ethor proto \\arp"; //第一个'\'为转义,设置arp过滤规则
bpf_program fcode;
tm* ltime;
char timestr[16];
time_t local_tv_sec;
pcap_pkthdr* header;
const u_char* pkt_data;
FILE* fp = fopen("ARP_log.txt", "w"); //日志流
u_int netmask;
u_char net_ip_addr[MAXNUM + 1][4];//网络设备的ip地址，假设网络设备最多10个
u_char net_mac_addr[6];
u_char dst_ip[4] = { 0xc0,0xa8,0x00,0x65 };
u_char dst_mac[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
u_char random_mac[6] = { 0x12, 0x24, 0x56, 0x78, 0x9a, 0xbc };//为获取本机mac设置的随机mac

/*获取适配器ip地址*/
char* iptos(u_long in, int num);
/*封装ARP数据包并广播发送*/
int sendARP(u_char* src_ip, u_char* dst_ip);
/*通过构造一个外来ARP请求获取当前网卡的MAC地址*/
int getMacAddr(int curAdapterNo);
/*打印ip或mac地址*/
void printMessage(u_char* addr, int type);


int main()
{

	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		fprintf(fp, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", i, d->name);
		fprintf(fp, "%d. %s", ++i, d->name);
		if (d->description) {
			printf(" (%s)\n", d->description);
			fprintf(fp, " (%s)\n", d->description);
		}
		else {
			printf(" (No description available)\n");
			fprintf(fp, " (No description available)\n");
		}
		//查询并保存网络设备的ip地址
		char* str = "0.0.0.0";
		for (pcap_addr_t* a = d->addresses; a; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				if (a->addr) {
					str = iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr, i);
					break;
				}
			}
		}
		printf("   IP Address: %s\n", str);
		fprintf(fp, "   IP Address: %s\n", str);
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("\nEnter the interface number (1-%d):", i);
	fprintf(fp, "\nEnter the interface number (1-%d):", i);
	scanf_s("%d", &inum);
	fprintf(fp, "%d\n", inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		fprintf(fp, "\nInterface number out of range.\n");
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
		fprintf(fp, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}


	int res = getMacAddr(inum);
	if (res != 0) {
		printf("Cannot get MAC address automatically, please input MAC address: ");
		fprintf(fp, "Cannot get MAC address automatically, please input MAC address: ");
		u_int temp;
		for (i = 0; i < 6; i++) {
			scanf_s("%d", &temp);
			net_mac_addr[i] = temp;
			fprintf(fp, "%d ", temp);
		}
		fprintf(fp, "\n");
	}
	char option;
	printf("\nUse default destination IP(192.168.0.101)? Y(y)/N(n): ");
	fprintf(fp, "\nUse default destination IP(192.168.0.101)? Y(y)/N(n): ");
	getchar();
	scanf_s("%c", &option, 1);
	fprintf(fp, "%c", option);
	if (option == 'N' || option == 'n') {
		printf("Input the IP Address of destination: ");
		fprintf(fp, "Input the IP Address of destination: ");
		u_int temp;
		for (i = 0; i < 4; i++) {
			scanf_s("%d", &temp);
			dst_ip[i] = temp;
			fprintf(fp, "%d ", temp);
		}
		fprintf(fp, "\n");
	}
	printf("\nThe MAC Address of Adapter %d: ", inum);
	fprintf(fp, "\nThe MAC Address of Adapter %d: ", inum);
	printMessage(net_mac_addr, MACADDR);
	printf("The IP Address of Adapter %d: ", inum);
	fprintf(fp, "The IP Address of Adapter %d: ", inum);
	printMessage(net_ip_addr[inum], IPADDR);
	printf("The IP Address of destination: ");
	fprintf(fp, "The IP Address of destination: ");
	printMessage(dst_ip, IPADDR);

	res = sendARP(net_ip_addr[inum], dst_ip);

	if (res == 0) {
		printf("\nSend packet successfully\n\n");
		fprintf(fp, "\nSend packet successfully\n\n");
	}
	else {
		printf("Failed to send packet due to: %d\n", GetLastError());
		fprintf(fp, "Failed to send packet due to: %d\n", GetLastError());
	}

	netmask = ((sockaddr_in*)((d->addresses)->netmask))->sin_addr.S_un.S_addr;
	pcap_compile(adhandle, &fcode, filter, 1, netmask);	//编译过滤器
	pcap_setfilter(adhandle, &fcode);	//设置过滤器

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);
	i = 0;

	printf("Catching packets...\n\n");
	fprintf(fp, "Catching packets...\n\n");

	int begin = -1;
	//获取数据包并解析
	while (res = pcap_next_ex(adhandle, &header, &pkt_data) >= 0) {
		//超时
		if (res == 0) {
			continue;
		}

		//解析ARP包，ARP包封装在MAC帧，MAC帧首部占14字节
		ArpHeader* arpheader = (ArpHeader*)(pkt_data + 14);
		if (begin != 0) {
			begin = memcmp(net_ip_addr[inum], arpheader->sip, sizeof(arpheader->sip));
			if (begin != 0) {
				continue;
			}
		}
		printf("message %d:\n", ++i);
		fprintf(fp, "message %d:\n", i);
		//设置标志，当收到之前发送的request的reply时结束捕获
		bool ok = false;
		if (arpheader->op == 256) {
			printf("request message.\n");
			fprintf(fp, "request message.\n");
		}
		else {
			printf("reply message.\n");
			fprintf(fp, "reply message.\n");
			//如果当前报文时reply报文，则通过比较ip来判断是否时之前发送的request对应的reply
			if (memcmp(arpheader->dip, net_ip_addr[inum], sizeof(arpheader->dip)) == 0) {
				memcpy(dst_mac, arpheader->smac, 6);
				ok = true;
			}
		}
		//获取以太网帧长度
		printf("ARP packet length: %d\n", header->len);
		fprintf(fp, "ARP packet length: %d\n", header->len);
		//获取时间戳
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
		printf("current time: %s\n", timestr);
		fprintf(fp, "current time: %s\n", timestr);
		//打印源ip
		printf("source ip: ");
		fprintf(fp, "source ip: ");
		printMessage(arpheader->sip, IPADDR);
		//打印目的ip
		printf("destination ip: ");
		fprintf(fp, "destination ip: ");
		printMessage(arpheader->dip, IPADDR);
		//打印源mac
		printf("source mac: ");
		fprintf(fp, "source mac: ");
		printMessage(arpheader->smac, MACADDR);
		//打印目的mac
		printf("destination mac: ");
		fprintf(fp, "destination mac: ");
		printMessage(arpheader->dmac, MACADDR);
		printf("\n\n");
		fprintf(fp, "\n\n");
		if (ok) {
			printf("Get the MAC address of destination: ");
			fprintf(fp, "Get the MAC address of destination: ");
			printMessage(dst_mac, MACADDR);
			printf("\nEnd of catching...\n\n");
			fprintf(fp, "\nEnd of catching...\n\n");
			break;
		}
	}
	fclose(fp);
	return 0;
}


/*获取适配器ip地址*/
char* iptos(u_long in, int num)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;

	p = (u_char*)& in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	memcpy(net_ip_addr[num], p, 4);
	return output[which];
}


/*封装ARP数据包并广播发送*/
int sendARP(u_char * src_ip, u_char * dst_ip)
{
	unsigned char sendbuf[42]; //arp包结构大小，42个字节
	EthHeader eh;
	ArpHeader ah;
	//赋值地址
	memcpy(eh.DestMAC, dst_mac, 6);   //以太网首部目的MAC地址，全为广播地址
	memcpy(eh.SourMAC, net_mac_addr, 6);   //以太网首部源MAC地址
	memcpy(ah.smac, net_mac_addr, 6);   //ARP字段源MAC地址
	memcpy(ah.dmac, dst_mac, 6);   //ARP字段目的MAC地址
	memcpy(ah.sip, src_ip, 4);   //ARP字段源IP地址
	memcpy(ah.dip, dst_ip, 4);
	eh.EthType = htons(ETH_ARP);   //htons：将主机的无符号短整形数转换成网络字节顺序
	ah.hdType = htons(HARDWARE);
	ah.proType = htons(ETH_IP);
	ah.hdSize = 6;
	ah.proSize = 4;
	ah.op = htons(REQUEST);
	memset(sendbuf, 0, sizeof(sendbuf));   //ARP清零
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
	return pcap_sendpacket(adhandle, sendbuf, 42);
}

/*捕获ARP数据包*/


/**
	通过构造一个外来ARP请求获取当前网卡的MAC地址
*/
int getMacAddr(int curAdapterNo)
{
	u_char src_ip[4] = { 0x12, 0x34, 0x56, 0x78 };
	u_char dst_ip[4];
	memcpy(dst_ip, net_ip_addr[curAdapterNo], 4);
	memcpy(net_mac_addr, random_mac, 6);
	int res = sendARP(src_ip, dst_ip);
	if (res != 0) {
		return -1;
	}
	while (res = pcap_next_ex(adhandle, &header, &pkt_data) >= 0) {
		if (res == 0) {
			continue;
		}
		ArpHeader* arph = (ArpHeader*)(pkt_data + 14);
		if (arph->op != 256) {
			if (memcmp(arph->dip, src_ip, sizeof(src_ip)) == 0) {
				memcpy(net_mac_addr, arph->smac, 6);
				break;
			}
		}
	}
	return 0;
}

/*打印ip地址或mac地址*/
void printMessage(u_char * addr, int type)
{
	int size = type == IPADDR ? 4 : 6;
	const char* format = type == IPADDR ? "%d." : "%02x-";
	const char* last = type == IPADDR ? "%d\n" : "%02x\n";
	for (int i = 0; i < size - 1; i++) {
		printf(format, addr[i]);
		fprintf(fp, format, addr[i]);
	}
	printf(last, addr[size - 1]);
	fprintf(fp, last, addr[size - 1]);
}
