#include "icmp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 处理一个收到的数据包
 *        你首先要检查buf长度是否小于icmp头部长度
 *        接着，查看该报文的ICMP类型是否为回显请求，
 *        如果是，则回送一个回显应答（ping应答），需要自行封装应答包。
 * 
 *        应答包封装如下：
 *        首先调用buf_init()函数初始化txbuf，然后封装报头和数据，
 *        数据部分可以拷贝来自接收到的回显请求报文中的数据。
 *        最后将封装好的ICMP报文发送到IP层。  
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TODO
    icmp_hdr_t * icmp = (icmp_hdr_t *)buf->data;
    // 检查buf长度是否小于icmp头部长度
    if(buf->len >= 8){       // icmp头部8B
        if(icmp->type == ICMP_TYPE_ECHO_REQUEST && icmp->code == 0){
            // 回送一个回显应答（ping应答）
            buf_copy(&txbuf, buf);

            icmp_hdr_t * icmptr = (icmp_hdr_t *)txbuf.data;
            // 改icmp头部
            icmptr->type = 0;
            icmptr->code = 0;

            // 将icmp报头的校验和清零
            icmptr->checksum = 0;

            icmptr->checksum = swap16(checksum16((uint16_t *)icmptr, txbuf.len));
            
            // 调ip_out, 加ip报头并发出
            ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);

        } 

    }
}

/**
 * @brief 发送icmp不可达
 *        你需要首先调用buf_init初始化buf，长度为ICMP头部 + IP头部 + 原始IP数据报中的前8字节 
 *        填写ICMP报头首部，类型值为目的不可达
 *        填写校验和
 *        将封装好的ICMP数据报发送到IP层。
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TODO

    buf_init(&txbuf, 20+8);           // 先复制
    memcpy(txbuf.data, recv_buf->data, 20+8);     // 是data位置赋值，而不是payload位置赋值！！！

    buf_add_header(&txbuf, 8);       // 加ICMP报头

    icmp_hdr_t * icmp = (icmp_hdr_t *)txbuf.data;
    icmp->type = ICMP_TYPE_UNREACH;                  // 填写ICMP报头
    icmp->code = code;

    icmp->checksum = 0;
    icmp->id = 0;
    icmp->seq = 0;
           
    icmp->checksum = swap16(checksum16((uint16_t *)icmp, txbuf.len));

    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
    
}