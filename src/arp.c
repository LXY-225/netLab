#include "arp.h"
#include "utils.h"
#include "ethernet.h"
#include "config.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type = swap16(ARP_HW_ETHER),
    .pro_type = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = DRIVER_IF_IP,                // 本机IP
    .sender_mac = DRIVER_IF_MAC,
    .target_mac = {0}};


/**
 * @brief arp地址转换表
 * 
 */
arp_entry_t arp_table[ARP_MAX_ENTRY];

/**
 * @brief 长度为1的arp分组队列，当等待arp回复时暂存未发送的数据包
 * 
 */
arp_buf_t arp_buf;

/**
 * @brief 更新arp表
 *        你首先需要依次轮询检测ARP表中所有的ARP表项是否有超时，如果有超时，则将该表项的状态改为无效。
 *        接着，查看ARP表是否有无效的表项，如果有，则将arp_update()函数传递进来的新的IP、MAC信息插入到表中，
 *        并记录超时时间，更改表项的状态为有效。
 *        如果ARP表中没有无效的表项，则找到超时时间最长的一条表项，
 *        将arp_update()函数传递进来的新的IP、MAC信息替换该表项，并记录超时时间，设置表项的状态为有效。
 * 
 * @param ip ip地址
 * @param mac mac地址
 * @param state 表项的状态
 */
void arp_update(uint8_t *ip, uint8_t *mac, arp_state_t state)
{
    // TODO

    time_t curtime;
    
    // 检查arp_table表项是否超时
    for(int i = 0; i < ARP_MAX_ENTRY; i++){
        time(&curtime);                            // 获取当前时间
        if(arp_table[i].state != ARP_INVALID && curtime - arp_table[i].timeout >= ARP_TIMEOUT_SEC){  // 表示超时
            arp_table[i].state = ARP_INVALID;
        }
    }

    int flag = 0;
    for(int i = 0; i < ARP_MAX_ENTRY; i++){
        if(arp_table[i].state == ARP_INVALID){  
            // 将arp_table[i] 替换
            //ip插入
            memcpy(arp_table[i].ip, ip, NET_IP_LEN);
            // mac插入
            memcpy(arp_table[i].mac, mac, NET_MAC_LEN);

            time(&arp_table[i].timeout);       // 记录下当前时间
            arp_table[i].state = state;                            // 有效

            flag = 1;
            break;     // 完成当前arp表项的替换
        }
    }
    if(!flag){    // 没有完成替换，即 arp表项的状态都不是ARP_INVALID

        time_t timeoutMax = 0;
        int indexMax = 0;

        for(int i = 0; i < ARP_MAX_ENTRY; i++){             // 找应被替换项
            if(arp_table[i].timeout > timeoutMax){      
                timeoutMax = arp_table[i].timeout;
                indexMax = i;
            }
        }
        
        // 将indexMax项替换掉
        //ip插入
        memcpy(arp_table[indexMax].ip, ip, NET_IP_LEN);
        // mac插入
        memcpy(arp_table[indexMax].mac, mac, NET_MAC_LEN);

        time(&arp_table[indexMax].timeout);;       // 记录下当前时间
        arp_table[indexMax].state = state;      // 有效
    }
    
}

/**
 * @brief 从arp表中根据ip地址查找mac地址
 * 
 * @param ip 欲转换的ip地址
 * @return uint8_t* mac地址，未找到时为NULL
 */
static uint8_t *arp_lookup(uint8_t *ip)
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        if (arp_table[i].state == ARP_VALID && memcmp(arp_table[i].ip, ip, NET_IP_LEN) == 0)
            return arp_table[i].mac;
    return NULL;
}

/**
 * @brief 发送一个arp请求
 *        你需要调用buf_init对txbuf进行初始化
 *        填写ARP报头，将ARP的opcode设置为ARP_REQUEST，注意大小端转换
 *        将ARP数据报发送到ethernet层
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
static void arp_req(uint8_t *target_ip)        
{
    // TODO
    buf_init(&txbuf, 28);     
    // 填写txbuf的报头
    arp_pkt_t *arp = (arp_pkt_t *)txbuf.data;
    arp->hw_type = swap16(ARP_HW_ETHER);         
    arp->pro_type = swap16(NET_PROTOCOL_IP);     
    arp->hw_len = NET_MAC_LEN;
    arp->pro_len = NET_IP_LEN;
    arp->opcode = swap16(ARP_REQUEST);     // 输出会反，但存的是大端，关键：发的时候是大端，即要存大端

    // 地址
    memcpy(arp->sender_ip, net_if_ip, NET_IP_LEN);
    memcpy(arp->sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(arp->target_ip, target_ip, NET_IP_LEN);            

    uint8_t boardcast_mac[] = {0xff,0xff,0xff,0xff,0xff,0xff};
    // memcpy(arp->target_mac, boardcast_mac, NET_MAC_LEN);    target_mac不填

    ethernet_out(&txbuf, boardcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，查看报文是否完整，
 *        检查项包括：硬件类型，协议类型，硬件地址长度，协议地址长度，操作类型
 *        
 *        接着，调用arp_update更新ARP表项
 *        查看arp_buf是否有效，如果有效，则说明ARP分组队列里面有待发送的数据包。
 *        即上一次调用arp_out()发送来自IP层的数据包时，由于没有找到对应的MAC地址进而先发送的ARP request报文
 *        此时，收到了该request的应答报文。然后，根据IP地址来查找ARM表项，如果能找到该IP地址对应的MAC地址，
 *        则将缓存的数据包arp_buf再发送到ethernet层。
 * 
 *        如果arp_buf无效，还需要判断接收到的报文是否为request请求报文，并且，该请求报文的目的IP正好是本机的IP地址，
 *        则认为是请求本机MAC地址的ARP请求报文，则回应一个响应报文（应答报文）。
 *        响应报文：需要调用buf_init初始化一个buf，填写ARP报头，目的IP和目的MAC需要填写为收到的ARP报的源IP和源MAC。
 * 
 * @param buf 要处理的数据包
 */
void arp_in(buf_t *buf)            
{
    // TODO
    // 报头检查，是否完整
    arp_pkt_t *arp = (arp_pkt_t *)buf->data;   // 数据部分 开始指针  buf是收到的数据包：大端存储
    
    uint16_t opcode = swap16(arp->opcode);            // 小端存储 = swap(大端存储)  ， arp->opcode大端存储，读是反的

    if(arp->hw_type != swap16(ARP_HW_ETHER)          
        || arp->pro_type != swap16(NET_PROTOCOL_IP)      // 大端存储 != swap(小端存储)
        || arp->hw_len != NET_MAC_LEN
        || arp->pro_len != NET_IP_LEN
        || (opcode != ARP_REQUEST && opcode != ARP_REPLY)
    ){
        // printf("检查包，发现error，报头不完整\n");
        return;
    }
        
    // 调用arp_update更新表项   
    arp_update(arp->sender_ip, arp->sender_mac, ARP_VALID);

    // 查看arp_buf
    if(arp_buf.valid == 1){     // 有待发包
        // 待发包的目的IP是？
        
        // arp_pkt_t *pr = (arp_pkt_t *)arp_buf.buf.data;   // 为什么用arp_buf.buf.data->target_ip 不对，还会有段错误？
        // uint8_t *mac = arp_lookup(pr->target_ip);       
        // 因为：arp_buf是暂存待发包，但是不一定是arp报文！！！可能是udp报文加了IP头，所以不可以用arp_buf.buf.data->target_ip 找目的IP
        

        uint8_t *mac = arp_lookup(arp_buf.ip);

        if(mac != NULL){   // 发包
            ethernet_out(&arp_buf.buf, mac, arp_buf.protocol);  
            arp_buf.valid = 0;          /// 发完之后要改为0！！！
        }

    }else{     // 无待发包
        // 请求本机MAC地址的ARP请求报文
        if(opcode == ARP_REQUEST && memcmp(arp->target_ip, net_if_ip, NET_IP_LEN) == 0){    

            buf_init(&rxbuf, 28);
            // 填写rxbuf的报头
            arp_pkt_t *rxp = (arp_pkt_t *)rxbuf.data;
            rxp->hw_type = swap16(ARP_HW_ETHER);         
            rxp->pro_type = swap16(NET_PROTOCOL_IP);     
            rxp->hw_len = NET_MAC_LEN;
            rxp->pro_len = NET_IP_LEN;
            rxp->opcode = swap16(ARP_REPLY);     //响应包

            // 地址
            memcpy(rxp->sender_ip, net_if_ip, NET_IP_LEN);
            memcpy(rxp->sender_mac, net_if_mac, NET_MAC_LEN);
            memcpy(rxp->target_ip, arp->sender_ip, NET_IP_LEN);            
            memcpy(rxp->target_mac, arp->sender_mac, NET_MAC_LEN);

            ethernet_out(&rxbuf, rxp->target_mac, NET_PROTOCOL_ARP);
        }
    }
}


/**
 * @brief 处理一个要发送的数据包
 *        你需要根据IP地址来查找ARP表
 *        如果能找到该IP地址对应的MAC地址，则将数据报直接发送给ethernet层
 *        如果没有找到对应的MAC地址，则需要先发一个ARP request报文。
 *        注意，需要将来自IP层的数据包缓存到arp_buf中，等待arp_in()能收到ARP request报文的应答报文
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TODO

    uint8_t *mac = arp_lookup(ip);
    if(mac){   // 找到VALID表项
        ethernet_out(buf, mac, protocol);
    }else{
        // 将arp包先缓存到arp_buf的buf中
        buf_copy(&arp_buf.buf, buf);

        arp_buf.valid = 1;  

        arp_buf.protocol = protocol;            // 暂存包的时候，要写上层协议和IP！！！查找ARP表用的IP就是待发包arp_buf.ip
        memcpy(arp_buf.ip, ip, NET_IP_LEN);
        
        // 调用apr_req函数，发一个arp请求报文
        arp_req(ip);
    }

}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    for (int i = 0; i < ARP_MAX_ENTRY; i++)
        arp_table[i].state = ARP_INVALID;
    arp_buf.valid = 0;       // 无效
    arp_req(net_if_ip);
}