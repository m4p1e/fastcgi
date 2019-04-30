/*
 * @filename:    fcgi.c
 * @author:      Tanswer
 * @date:        2017年12月23日 00:00:09
 * @description:
 */


#define _BASE64_H 

#include "fastcgi.h"
#include "fcgi.h"

#include <stdlib.h>  

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/un.h>

static const int PARAMS_BUFF_LEN = 2048;  //环境参数buffer的大小
static const int CONTENT_BUFF_LEN = 2048; //内容buffer的大小

unsigned char *base64_encode(unsigned char *str,long str_len)  
{  
    long len;  
    //long str_len;  
    unsigned char *res;  
    int i,j;  
//定义base64编码表  
    unsigned char *base64_table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";  
  
//计算经过base64编码后的字符串长度  
    //str_len=strlen(str);  
    if(str_len % 3 == 0)  
        len=str_len/3*4;  
    else  
        len=(str_len/3+1)*4;  
  
    res=malloc(sizeof(unsigned char)*len+1);  
    res[len]='\0';  
  
//以3个8位字符为一组进行编码  
    for(i=0,j=0;i<len-2;j+=3,i+=4)  
    {  
        res[i]=base64_table[str[j]>>2]; //取出第一个字符的前6位并找出对应的结果字符  
        res[i+1]=base64_table[(str[j]&0x3)<<4 | (str[j+1]>>4)]; //将第一个字符的后位与第二个字符的前4位进行组合并找到对应的结果字符  
        res[i+2]=base64_table[(str[j+1]&0xf)<<2 | (str[j+2]>>6)]; //将第二个字符的后4位与第三个字符的前2位组合并找出对应的结果字符  
        res[i+3]=base64_table[str[j+2]&0x3f]; //取出第三个字符的后6位并找出结果字符  
    }  
  
    switch(str_len % 3)  
    {  
        case 1:  
            res[i-2]='=';  
            res[i-1]='=';  
            break;  
        case 2:  
            res[i-1]='=';  
            break;  
    }  
  
    return res;  
}  
  
unsigned char *base64_decode(unsigned char *code)  
{  
//根据base64表，以字符找到对应的十进制数据  
    int table[]={0,0,0,0,0,0,0,0,0,0,0,0,
             0,0,0,0,0,0,0,0,0,0,0,0,
             0,0,0,0,0,0,0,0,0,0,0,0,
             0,0,0,0,0,0,0,62,0,0,0,
             63,52,53,54,55,56,57,58,
             59,60,61,0,0,0,0,0,0,0,0,
             1,2,3,4,5,6,7,8,9,10,11,12,
             13,14,15,16,17,18,19,20,21,
             22,23,24,25,0,0,0,0,0,0,26,
             27,28,29,30,31,32,33,34,35,
             36,37,38,39,40,41,42,43,44,
             45,46,47,48,49,50,51
               };  
    long len;  
    long str_len;  
    unsigned char *res;  
    int i,j;  
  
//计算解码后的字符串长度  
    len=strlen(code);  
//判断编码后的字符串后是否有=  
    if(strstr(code,"=="))  
        str_len=len/4*3-2;  
    else if(strstr(code,"="))  
        str_len=len/4*3-1;  
    else  
        str_len=len/4*3;  
  
    res=malloc(sizeof(unsigned char)*str_len+1);  
    res[str_len]='\0';  
  
//以4个字符为一位进行解码  
    for(i=0,j=0;i < len-2;j+=3,i+=4)  
    {  
        res[j]=((unsigned char)table[code[i]])<<2 | (((unsigned char)table[code[i+1]])>>4); //取出第一个字符对应base64表的十进制数的前6位与第二个字符对应base64表的十进制数的后2位进行组合  
        res[j+1]=(((unsigned char)table[code[i+1]])<<4) | (((unsigned char)table[code[i+2]])>>2); //取出第二个字符对应base64表的十进制数的后4位与第三个字符对应bas464表的十进制数的后4位进行组合  
        res[j+2]=(((unsigned char)table[code[i+2]])<<6) | ((unsigned char)table[code[i+3]]); //取出第三个字符对应base64表的十进制数的后2位与第4个字符进行组合  
    }  
  
    return res;  
  
}

void FastCgi_init(FastCgi_t *c)
{
    c->sockfd_ = 0;    //与php-fpm 建立的 sockfd
    c->flag_ = 0;      //record 里的请求ID
    c->requestId_ = 0; //用来标志当前读取内容是否为html内容
}

void FastCgi_finit(FastCgi_t *c)
{
    close(c->sockfd_);
}

void setRequestId(FastCgi_t *c, int requestId)
{
    c->requestId_ = requestId;
}

FCGI_Header makeHeader(int type, int requestId,
                       int contentLength, int paddingLength)
{
    FCGI_Header header;

    header.version = FCGI_VERSION_1;

    header.type = (unsigned char)type;

    /* 两个字段保存请求ID */
    header.requestIdB1 = (unsigned char)((requestId >> 8) & 0xff);
    header.requestIdB0 = (unsigned char)(requestId & 0xff);

    /* 两个字段保存内容长度 */
    header.contentLengthB1 = (unsigned char)((contentLength >> 8) & 0xff);
    header.contentLengthB0 = (unsigned char)(contentLength & 0xff);

    /* 填充字节的长度 */
    header.paddingLength = (unsigned char)paddingLength;

    /* 保存字节赋为 0 */
    header.reserved = 0;

    return header;
}

FCGI_BeginRequestBody makeBeginRequestBody(int role, int keepConnection)
{
    FCGI_BeginRequestBody body;

    /* 两个字节保存期望 php-fpm 扮演的角色 */
    body.roleB1 = (unsigned char)((role >> 8) & 0xff);
    body.roleB0 = (unsigned char)(role & 0xff);

    /* 大于0长连接，否则短连接 */
    body.flags = (unsigned char)((keepConnection) ? FCGI_KEEP_CONN : 0);

    bzero(&body.reserved, sizeof(body.reserved));

    return body;
}

int makeNameValueBody(char *name, int nameLen,
                      char *value, int valueLen,
                      unsigned char *bodyBuffPtr, int *bodyLenPtr)
{
    /* 记录 body 的开始位置 */
    unsigned char *startBodyBuffPtr = bodyBuffPtr;

    /* 如果 nameLen 小于128字节 */
    if (nameLen < 128)
    {
        *bodyBuffPtr++ = (unsigned char)nameLen; //nameLen用1个字节保存
    }
    else
    {
        /* nameLen 用 4 个字节保存 */
        *bodyBuffPtr++ = (unsigned char)((nameLen >> 24) | 0x80);
        *bodyBuffPtr++ = (unsigned char)(nameLen >> 16);
        *bodyBuffPtr++ = (unsigned char)(nameLen >> 8);
        *bodyBuffPtr++ = (unsigned char)nameLen;
    }

    /* valueLen 小于 128 就用一个字节保存 */
    if (valueLen < 128)
    {
        *bodyBuffPtr++ = (unsigned char)valueLen;
    }
    else
    {
        /* valueLen 用 4 个字节保存 */
        *bodyBuffPtr++ = (unsigned char)((valueLen >> 24) | 0x80);
        *bodyBuffPtr++ = (unsigned char)(valueLen >> 16);
        *bodyBuffPtr++ = (unsigned char)(valueLen >> 8);
        *bodyBuffPtr++ = (unsigned char)valueLen;
    }

    /* 将 name 中的字节逐一加入body中的buffer中 */
    for (int i = 0; i < strlen(name); i++)
    {
        *bodyBuffPtr++ = name[i];
    }

    /* 将 value 中的值逐一加入body中的buffer中 */
    for (int i = 0; i < strlen(value); i++)
    {
        *bodyBuffPtr++ = value[i];
    }

    /* 计算出 body 的长度 */
    *bodyLenPtr = bodyBuffPtr - startBodyBuffPtr;
    return 1;
}

/*
 * 如果有配置文件的话，可以将一些信息，比如IP 从配置文件里读出来
 *
char *getIpFromConf()
{
    return getMessageFromFile("IP");
}
*/

void startConnect(FastCgi_t *c)
{
    int rc;
    int sockfd;
    struct sockaddr_un server_address;

    /* 固定 */
    const char *ip = "/run/php/php7.3-fpm.sock";

    /* 获取配置文件中的ip地址 */
    //ip = getIpFromConf();

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(sockfd > 0);

    bzero(&server_address, sizeof(server_address));

    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path,ip);
    //server_address.sin_addr.s_addr = inet_addr(ip);
    //server_address.sin_port = htons(9000);

    rc = connect(sockfd, (struct sockaddr *)&server_address, sizeof(server_address));
    perror("connect: ");
    assert(rc >= 0);

    c->sockfd_ = sockfd;
}
int sendStartRequestRecord(FastCgi_t *c)
{
    int rc;
    FCGI_BeginRequestRecord beginRecord;

    beginRecord.header = makeHeader(FCGI_BEGIN_REQUEST, c->requestId_, sizeof(beginRecord.body), 0);
    beginRecord.body = makeBeginRequestBody(FCGI_RESPONDER, 0);
    //printf("%s\n", );
    printf("%s",base64_encode((char *)&beginRecord,sizeof(beginRecord)));
    rc = write(c->sockfd_, (char *)&beginRecord, sizeof(beginRecord));
    assert(rc == sizeof(beginRecord));

    return 1;
}

int sendParams(FastCgi_t *c, char *name, char *value)
{
    int rc;

    unsigned char bodyBuff[PARAMS_BUFF_LEN];

    bzero(bodyBuff, sizeof(bodyBuff));

    /* 保存 body 的长度 */
    int bodyLen;

    /* 生成 PARAMS 参数内容的 body */
    makeNameValueBody(name, strlen(name), value, strlen(value), bodyBuff, &bodyLen);

    FCGI_Header nameValueHeader;
    nameValueHeader = makeHeader(FCGI_PARAMS, c->requestId_, bodyLen, 0);
    /*8 字节的消息头*/

    int nameValueRecordLen = bodyLen + FCGI_HEADER_LEN;
    char nameValueRecord[nameValueRecordLen];

    /* 将头和body拷贝到一块buffer 中只需调用一次write */
    memcpy(nameValueRecord, (char *)&nameValueHeader, FCGI_HEADER_LEN);
    memcpy(nameValueRecord + FCGI_HEADER_LEN, bodyBuff, bodyLen);
    printf("%s",base64_encode(nameValueRecord,nameValueRecordLen));
    rc = write(c->sockfd_, nameValueRecord, nameValueRecordLen);
    assert(rc == nameValueRecordLen);

    return 1;
}

int sendEndRequestRecord(FastCgi_t *c)
{
    int rc;

    FCGI_Header endHeader;
    endHeader = makeHeader(FCGI_PARAMS, c->requestId_, 0, 0);
    printf("%s",base64_encode((char *)&endHeader,FCGI_HEADER_LEN));
    rc = write(c->sockfd_, (char *)&endHeader, FCGI_HEADER_LEN);
    assert(rc == FCGI_HEADER_LEN);

    return 1;
}

void readFromPhp(FastCgi_t *c , char *cs)
{
    FCGI_Header responderHeader;
    char content[CONTENT_BUFF_LEN];

    int contentLen;
    char tmp[8]; //用来暂存padding字节
    int ret;

    /* 先将头部 8 个字节读出来 */
    while (read(c->sockfd_, &responderHeader, FCGI_HEADER_LEN) > 0)
    {
        if (responderHeader.type == FCGI_STDOUT)
        {
            /* 获取内容长度 */
            contentLen = (responderHeader.contentLengthB1 << 8) + (responderHeader.contentLengthB0);
            bzero(content, CONTENT_BUFF_LEN);

            /* 读取获取内容 */
            ret = read(c->sockfd_, content, contentLen);
            // printf("ret ==  %d\n", ret);

            assert(ret == contentLen);

            /*test*/
            //printf("content == %s", content);

            /* 跳过填充部分 */
            if (responderHeader.paddingLength > 0)
            {
                ret = read(c->sockfd_, tmp, responderHeader.paddingLength);
                assert(ret == responderHeader.paddingLength);
            }
        } //end of type FCGI_STDOUT
        else if (responderHeader.type == FCGI_STDERR)
        {
            contentLen = (responderHeader.contentLengthB1 << 8) + (responderHeader.contentLengthB0);
            bzero(content, CONTENT_BUFF_LEN);

            ret = read(c->sockfd_, content, contentLen);
            assert(ret == contentLen);

            fprintf(stdout, "error:%s", content);

            /* 跳过填充部分 */
            if (responderHeader.paddingLength > 0)
            {
                ret = read(c->sockfd_, tmp, responderHeader.paddingLength);
                assert(ret == responderHeader.paddingLength);
            }
        } // end of type FCGI_STDERR
        else if (responderHeader.type == FCGI_END_REQUEST)
        {
            FCGI_EndRequestBody endRequest;

            ret = read(c->sockfd_, &endRequest, sizeof(endRequest));
            assert(ret == sizeof(endRequest));
        }
    }
    strcpy(cs,content);
}

char *findStartHtml(char *p)
{
    enum
    {
        S_NOPE,
        S_CR,
        S_CRLF,
        S_CRLFCR,
        S_CRLFCRLF
    } state = S_NOPE;

    for (char *content = p; *content != '\0'; content++) //状态机
    {
        switch (state)
        {
        case S_NOPE:
            if (*content == '\r')
                state = S_CR;
            break;
        case S_CR:
            state = (*content == '\n') ? S_CRLF : S_NOPE;
            break;
        case S_CRLF:
            state = (*content == '\r') ? S_CRLFCR : S_NOPE;
            break;
        case S_CRLFCR:
            state = (*content == '\n') ? S_CRLFCRLF : S_NOPE;
            break;
        case S_CRLFCRLF:
            return content;
        }
    }
    // fprintf(stderr, "%%%%%%%%%%RETURN NULL!!!!!\n");
    return p;
}
void getHtmlFromContent(FastCgi_t *c, char *content)
{
    /* 保存html内容开始位置 */
    char *pt;

    /* 读取到的content是html内容 */
    if (c->flag_ == 1)
    {
        printf("%s", content);
    }
    else
    {
        if ((pt = findStartHtml(content)) != NULL)
        {
            c->flag_ = 1;
            for (char *i = pt; *i != '\0'; i++)
            {
                printf("%c", *i);
            }
        }
    }
}