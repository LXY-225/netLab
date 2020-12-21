#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include <string.h>

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，检查项包括：版本号、总长度、首部长度等。
 * 
 *        接着，计算头部校验和，注意：需要先把头部校验和字段缓存起来，再将校验和字段清零，
 *        调用checksum16()函数计算头部检验和，比较计算的结果与之前缓存的校验和是否一致，
 *        如果不一致，则不处理该数据报。
 * 
 *        检查收到的数据包的目的IP地址是否为本机的IP地址，只处理目的IP为本机的数据报。
 * 
 *        检查IP报头的协议字段：
 *        如果是ICMP协议，则去掉IP头部，发送给ICMP协议层处理
 *        如果是UDP协议，则去掉IP头部，发送给UDP协议层处理
 *        如果是本实验中不支持的其他协议，则需要调用icmp_unreachable()函数回送一个ICMP协议不可达的报文。
 *          
 * @param buf 要处理的包
 */
void ip_in(buf_t *buf)
{
    // TODO 

    ip_hdr_t *ip = (ip_hdr_t *)buf->data;   // 数据部分 开始指针  buf是收到的数据包：大端存储
    
    if(ip->version != IP_VERSION_4
        || ip->hdr_len > 6 
        || ip->hdr_len < 5){                 // 待补充

        return;
    }

    uint16_t check = swap16(ip->hdr_checksum);    // 缓存头部校验和

    ip->hdr_checksum = 0; 
    uint16_t checkans = checksum16((uint16_t *)ip, 20);    // 计算得到的校验和

    ip->hdr_checksum = swap16(check);      // 恢复

    // 下面去掉IP头部之前，先获得源IP
    uint8_t src_IP[NET_IP_LEN];
    memcpy(src_IP, ip->src_ip, NET_IP_LEN);

    if(checkans == check){
        // 校验和一致
        if(memcmp(ip->dest_ip, net_if_ip, NET_IP_LEN) == 0){
            // 是本机的IP报
            if(ip->protocol == NET_PROTOCOL_ICMP){   // 1个字节
                buf_remove_header(buf, IP_HDR_LEN_PER_BYTE * (ip->hdr_len));     // 4*  !!!
                    
                icmp_in(buf, src_IP);    // 通过接收的包的头部，可以得知：源IP

            }else if(ip->protocol == NET_PROTOCOL_UDP){
                buf_remove_header(buf, IP_HDR_LEN_PER_BYTE * (ip->hdr_len)); 
   
                udp_in(buf, src_IP);    // 通过接收的包的头部，可以得知：源IP

            }else{
                
                icmp_unreachable(buf, src_IP, ICMP_CODE_PROTOCOL_UNREACH);    // 协议不可达
            }
            
        }else{
            ;  // 不处理该数据报
        }
        
    }else{
        ;   // 不处理该数据报
    }

}

/**
 * @brief 处理一个要发送的分片
 *        你需要调用buf_add_header增加IP数据报头部缓存空间。
 *        填写IP数据报头部字段。
 *        将checksum字段填0，再调用checksum16()函数计算校验和，并将计算后的结果填写到checksum字段中。
 *        将封装后的IP数据报发送到arp层。
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TODO
    buf_add_header(buf, 20);

    ip_hdr_t * iptr = (ip_hdr_t *)buf->data;
    iptr->version = IP_VERSION_4;
    iptr->hdr_len = 5;
    iptr->tos = 0;
    iptr->total_len = swap16(buf->len);     // 大小端
    iptr->id = swap16(id);                 // 大小端！！！

    // 标志第2位：未考虑
    if(mf == 1){
        iptr->flags_fragment = offset | IP_MORE_FRAGMENT;
    }else{
        iptr->flags_fragment = offset;
    }

    iptr->ttl = IP_DEFALUT_TTL;

    /// 还要填充源IP和目的IP！ 先填充完全，才计算checksum
    memcpy(iptr->dest_ip, ip, NET_IP_LEN);
    memcpy(iptr->src_ip, net_if_ip, NET_IP_LEN);

    iptr->protocol = protocol;
    iptr->hdr_checksum = 0;

    iptr->hdr_checksum = swap16(checksum16((uint16_t *)iptr, 20));       // 打印出来看着正着的(即大端)数据，其实存的都是反的(即小端)

    arp_out(buf, ip, NET_PROTOCOL_IP);        // 传入的protocol应该是IP！
    
}

/**
 * @brief 处理一个要发送的数据包
 *        你首先需要检查需要发送的IP数据报是否大于以太网帧的最大包长（1500字节 - ip包头长度）。
 *        
 *        如果超过，则需要分片发送。 
 *        分片步骤：
 *        （1）调用buf_init()函数初始化buf，长度为以太网帧的最大包长（1500字节 - ip包头头长度）
 *        （2）将数据报截断，每个截断后的包长度 = 以太网帧的最大包长，调用ip_fragment_out()函数发送出去
 *        （3）如果截断后最后的一个分片小于或等于以太网帧的最大包长，
 *             调用buf_init()函数初始化buf，长度为该分片大小，再调用ip_fragment_out()函数发送出去
 *             注意：最后一个分片的MF = 0
 *    
 *        如果没有超过以太网帧的最大包长，则直接调用调用ip_fragment_out()函数发送出去。
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议             // 我：用于分解这个包，往上层送；而分片，所填的协议，要和原报一样
 */

#define pac_len 1480           // ip包头长度定长20, 则 数据max长度 1500-20=1480
int g_id = 0;         // 全局id号，以0开始，并未随机初始化

void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TODO 
    uint16_t len = buf->len;         // 16位  

    if(len > pac_len){       
        int num = 0;      // 第num个包，offset应该为：1480*num/8
        do{                                                                         // 非最后一个分片
            buf_init(&txbuf, pac_len);
            memcpy(txbuf.payload, buf->payload, pac_len);
            buf->data += pac_len;
            len -= pac_len;

            ip_fragment_out(&txbuf, ip, protocol, g_id, pac_len*num/8, 1);     // 分片完成，去加IP头

            num++;

        }while(len > 1480);
                                                                                    // 最后一个分片
        buf_init(&txbuf, len);
        memcpy(txbuf.payload, buf->payload, len);     // 数据部分，有待ip_fragment_out为其添加IP头部

        ip_fragment_out(&txbuf, ip, protocol, g_id, pac_len*num/8, 0);
    }else{
        // 不用分片，直接发出
        ip_fragment_out(buf, ip, protocol, g_id, 0, 0);
    }

    g_id++;    // 全局id ++ ，完成了一个数据报
}
