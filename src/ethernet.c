#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 处理一个收到的数据包
 *        你需要判断以太网数据帧的协议类型，注意大小端转换
 *        如果是ARP协议数据包，则去掉以太网包头，发送到arp层处理arp_in()
 *        如果是IP协议数据包，则去掉以太网包头，发送到IP层处理ip_in()
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TODO

    uint8_t *p = (buf->data) + 2 * NET_MAC_LEN;  // p指向 2B类型，收到的包：大端存储
    // printf("p[0] = %02x\n", p[0]);
    // printf("p[1] = %02x\n", p[1]);
    uint16_t *x = (uint16_t *) p;        // 指针强转，大读，则变成小端存储
    uint16_t value = *x;
    // printf("value = %04x\n", value);

    value = swap16(value);
    // printf("after swap16 : value = %04x\n\n",value);


    if(value == 0x0806){     // ARP
        buf_remove_header(buf, 2*NET_MAC_LEN+2);
        arp_in(buf);

    }else if(value == 0x0800){  // IP
        buf_remove_header(buf, 2*NET_MAC_LEN+2);
        ip_in(buf);
    }else{
        ;
    }
}

/**
 * @brief 处理一个要发送的数据包
 *        你需添加以太网包头，填写目的MAC地址、源MAC地址、协议类型
 *        添加完成后将以太网数据帧发送到驱动层
 * 
 * @param buf 要处理的数据包
 * @param mac 目标mac地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TODO
    uint8_t *p = NULL;

    buf_add_header(buf, 2+2*NET_MAC_LEN);
    p = buf->data;
    
    memcpy(p, mac, NET_MAC_LEN);
    p += NET_MAC_LEN;
    

    uint8_t arr[6] = DRIVER_IF_MAC;
    memcpy(p, arr, NET_MAC_LEN);
    p += NET_MAC_LEN;

    
    uint16_t *pro = (uint16_t *)p;

    // printf("\nprotocol = %04x\n", protocol);     // 0806
    *pro = protocol;        // 同等类型，直接赋值，实际：小端存储
    // printf("*pro = %04x\n", *pro);             //0806

    // printf("p[0] = %02x\n", p[0]);             //06
    // printf("p[1] = %02x\n\n", p[1]);          //08
    *pro = swap16(*pro);                 // 要转一下
    // printf("*pro = %04x\n", *pro);             //0608

    // printf("p[0] = %02x\n", p[0]);             //08
    // printf("p[1] = %02x\n\n", p[1]);          //06
    
    driver_send(buf);
}

/**
 * @brief 初始化以太网协议
 * 
 * @return int 成功为0，失败为-1
 */
int ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MTU + sizeof(ether_hdr_t));
    return driver_open();
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}