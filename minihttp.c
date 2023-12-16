#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>
#include <malloc.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#define SERVER_PORT 443
#define SECOND_SERVER_PORT 80
#define SERVER_CERT "./keys/cnlab.cert"
#define SERVER_KEY "./keys/cnlab.prikey"
#define UPLOAD_SIZE 1024*1024*5

// 定义一个结构体，往线程中传入多个参数
struct ThreadArgs {
    int  client_socket;       //代表客户端的socket  
    SSL* ssl;                 //代表ssl连接
};

static int debug = 1;
long prev_position = 0;                                //记录断点续传的上一次的位置
int flag = 0;                                          //判断是否为第一次响应（浏览器端） 
int isVLC = 0;                                         //判断是否为VLC端，如果是为1，如果为0，则为浏览器端（否）。

int   get_line(SSL* ssl,char *buffer,int size);
void* do_https_request(void* args);
void  do_https_response(SSL* ssl,const char* path);
void  not_found(SSL* ssl);
void  inner_error(SSL* ssl);
void  bad_request(SSL* ssl);
void  unimplemented(SSL* ssl);
void  moved_permanently(int client_socket);
void  send_video_to_browser(SSL* ssl,FILE* resource);
void  send_video_to_vlc(SSL* ssl,FILE* resource);
int   send_response_headers(SSL* ssl,FILE* resource);
void  send_response_body(SSL* ssl,FILE* resource);
void* accept_request(void* args);


int main(void){
    pthread_t id;                                   //表示这个线程的句柄(443)
    pthread_t second_id;                            //表示这个线程的句柄(80)
    int* server_port;                               //表示服务器监听的端口（443）
    int* second_server_port;                        //表示服务器监听的端口（80）
                                                    // Set TCP Keep-Alive to handle idle connections
    server_port = (int*)malloc(sizeof(int));        
    second_server_port = (int*)malloc(sizeof(int));
    *server_port = SERVER_PORT;                            //开启443线程
    pthread_create(&id,NULL,accept_request,server_port);
    *second_server_port = SECOND_SERVER_PORT;              //开启80线程
    pthread_create(&second_id,NULL,accept_request,second_server_port);
    //主线程阻塞，直到上述两个线程执行完之后，才继续执行
    pthread_join(id,NULL);
    pthread_join(second_id,NULL);
    return 0;
}


void* accept_request(void* args){
    int server_socket,client_socket;                //服务器、客户端的Socket
    struct sockaddr_in server_address;              //服务器的IP地址和端口号
    struct sockaddr_in client_address;              //客户端的IP地址和端口号
    socklen_t client_address_length;                //客户端的IP地址的长度
    client_address_length = sizeof(client_address);
    int server_port = *((int*)args);                //得到端口号
    pthread_t id;                                   //代表线程句柄
    SSL_CTX *ctx;                                   //SSL上下文
    SSL *ssl;                                       //表示ssl连接
                                                    //443 加载ssl
    if(server_port == 443){
        /*--ssl--*/
        // 1. 初始化 OpenSSL
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        // 2. 创建 SSL 上下文
        ctx = SSL_CTX_new(SSLv23_server_method());
        if(!ctx){
            fprintf(stderr,"Error creating SSL context\n");
            return NULL;
        }

        // 3. 加载服务器证书和私钥
        if(SSL_CTX_use_certificate_file(ctx,SERVER_CERT,SSL_FILETYPE_PEM) <= 0 ||SSL_CTX_use_PrivateKey_file(ctx,SERVER_KEY,SSL_FILETYPE_PEM) <= 0){
            fprintf(stderr,"Error loading server certificate or private key\n");
            return NULL;
        } 
    }
    /* 1. 创建服务器的socket
       参数: 
       AF_INET -> 使用IPV4
       SOCK_STREAM -> 使用TCP
     */
    server_socket = socket(AF_INET,SOCK_STREAM,0);
    // 2. 清空服务器IP地址以及写入服务器IP地址和端口号
    bzero(&server_address,sizeof(server_address));
    server_address.sin_family = AF_INET;                 // ipv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);  // 服务器端监听所有IP地址
    if(server_port == 443){
        server_address.sin_port = htons(SERVER_PORT);        // 服务器端指定端口号443
    }else{
        server_address.sin_port = htons(SECOND_SERVER_PORT); // 服务器端指定端口号80
    }
    // 3. 将服务器的IP地址和端口号绑定到服务器的socket
    bind(server_socket,(struct sockaddr *)&server_address,sizeof(server_address));
    // 4. 服务器开始监听
    listen(server_socket,1024);
    if(server_port == 443){
        printf("wait client message 443 .....\n");
    }else{
        printf("wait client message 80 .....\n");
    }

    // 开始处理客户端请求
    int done = 1; 
    while(done){
        char client_ip_address[64];
        // 开始接收客户端请求，获得跟客户端连接的socket
        client_socket = accept(server_socket,(struct sockaddr *)&client_address,&client_address_length);
        // 打印客户端IP地址和端口号
        printf("client ip: %s\tport: %d\n",inet_ntop(AF_INET,&client_address.sin_addr.s_addr,client_ip_address,sizeof(client_ip_address)),ntohs(client_address.sin_port));
        if(server_port == 443){
            // 创建 SSL 连接
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl,client_socket);
            // 创建 SSL 连接
            if (SSL_accept(ssl) <= 0){
                printf("1\n\n\n");
                ERR_print_errors_fp(stderr);
            }else{
                // 构造参数
                struct ThreadArgs* args = (struct ThreadArgs*)malloc(sizeof(struct ThreadArgs));
                args->client_socket = client_socket;
                args->ssl = ssl;
                // 开启线程处理https请求
                //pthread_create(&id,NULL,do_https_request,args);    
                do_https_request(args);
            }
        }else{
            moved_permanently(client_socket);
        }
    }
    // 关闭SSL上下文
    SSL_CTX_free(ctx);
    // 断开服务器的socket
    close(server_socket);
    return NULL;
}

void* do_https_request(void* args){
    int len = 0;                //一行的长度
    char buffer[256];           //一行的内容
    char method[64];            //读到的方法
    char url[256];              //读到的url
    char path[1024];            //代表主页文件的路径
    struct stat st;             //代表文件元数据的结构体
    int  client_socket;         //客户端的socket
    SSL* ssl;                   //ssl连接

    struct ThreadArgs* thread_args = (struct ThreadArgs*)args;
    client_socket = thread_args->client_socket;
    ssl = thread_args->ssl;

    //读取客户端发送的https请求（一次读一行)

    // 1. 读取请求行
    len = get_line(ssl,buffer,sizeof(buffer));
    printf("buffer:%s\n",buffer);
    if(len > 0){        //读到了请求行
        int i = 0, j = 0;
        // 1.1  读取请求方法
        while(!isspace(buffer[j]) && i < sizeof(method) - 1){
            method[i] = buffer[j];
            i++;
            j++;  
        }
        method[i] = '\0';
        if(debug) printf("request method: %s\n",method);
        //  1.2 读取请求url
        if(strncasecmp(method,"GET",i) == 0){        //只处理get请求
            if(debug) printf("method = GET\n");
            //获取url
            while(isspace(buffer[j])){               //跳过空格
                j++;
            }
            i = 0;
            while(!isspace(buffer[j]) && i < sizeof(url) - 1){
                url[i] = buffer[j];
                i++;
                j++;
            }
            url[i] = '\0';
            if(debug) printf("url: %s\n",url);
            // 1.3  继续读取http头部,并处理User-Agent:行
            do{
                len = get_line(ssl,buffer,sizeof(buffer));
                if(debug) printf("SSL_read line: %s\n",buffer);
                // 判断是否为VLC端
                if(strstr(buffer,"VLC")){
                    isVLC = 1;
                }
            }while(len > 0);
            //定位服务器本地的html文件

            //处理url中的？
            char * pos = strchr(url,'?');
            //如果找到了
            if(pos){
                //把参数截掉
                *pos = '\0';
            }
            if(debug) printf("real url:%s\n",url);
            // 指定主页文件的path
            sprintf(path,"./dir%s",url);

            if(debug) printf("index.html's path:%s\n",path);
            //执行http响应
            //判断文件是否存在，如果存在就响应200 OK，同时发送响应的html 文件，如果不存在，就响应 404 NOT FOUND.
            if(stat(path,&st) == -1){//文件不存在或是出错
                fprintf(stderr,"stat %s failed. reason: %s\n",path,strerror(errno));
                not_found(ssl);
            }else{//文件存在
                  //如果请求的是目录，那么在后面自动补全/index.html
                if(S_ISDIR(st.st_mode)){
                    strcat(path,"/index.html");
                }
                do_https_response(ssl,path);
            }
        }else{//非GET请求，读取http头部，并响应客户端501状态码
            fprintf(stderr,"warning! other request [%s]\n",method);
            do{
                len = get_line(ssl,buffer,sizeof(buffer));
                if(debug) printf("SSL_read line: %s\n",buffer);
            }while(len > 0);
            unimplemented(ssl);          //响应客户端501状态码
        }
    }else {//请求格式有问题，出错处理，并响应客户端400状态码
        bad_request(ssl);            //响应客户端400状态码
    }
    // 结束与客户端的socket
    close(client_socket);
    // 关闭 SSL 连接
    SSL_shutdown(ssl);
    SSL_free(ssl);    
    // 释放动态分配的内存
    if(thread_args) free(thread_args);
    return NULL;
}

void do_https_response(SSL* ssl,const char* path){
    int ret = 0;
    FILE *resource = NULL;

    resource = fopen(path,"rb");
    if(resource == NULL){
        not_found(ssl);
        return;
    }

    //TODO -> 分别处理.html和.mp4文件
    if(strstr(path,".html")){ 
        //1. 发送http 响应头
        ret = send_response_headers(ssl,resource);
        //2. 发送http 响应体
        if(!ret){
            send_response_body(ssl,resource);
        }   
    }else{
        //处理mp4文件
        if(!isVLC){ //browser
            printf("1\n");
            send_video_to_browser(ssl,resource);
        }else{      //vlc
            printf("2\n");
            send_video_to_vlc(ssl,resource);
            isVLC = 0;
        }
    }
    fclose(resource);
}

int send_response_headers(SSL* ssl,FILE* resource){
    struct stat st;                 //文件元数据
    int file_id = 0;                //文件描述符
    char tmp[64];                   //Content-Length
    char buffer[1024] = {0};        //响应头
    strcpy(buffer,"HTTP/1.0 200 OK\r\n");
    strcat(buffer,"Server: Gao79135 Server\r\n");
    strcat(buffer,"Content-Type: text/html\r\n");
    strcat(buffer,"Connection: Close\r\n");
    file_id = fileno(resource);

    if(fstat(file_id,&st) == -1){
        //返回服务器内部错误：500
        inner_error(ssl);
        return -1;
    }

    snprintf(tmp,64,"Content-Length: %ld\r\n\r\n",st.st_size);
    strcat(buffer,tmp);

    if(debug) fprintf(stdout,"response header: %s\n",buffer);

    //响应给服务器
    if(SSL_write(ssl,buffer,strlen(buffer)) < 0){
        fprintf(stderr,"send failed. data: %s, reason: %s\n",buffer,strerror(errno));
        return -1;
    }
    return 0;
}
/*
   实现将html文件的内容按行读取并送给客户端
 */
void send_response_body(SSL* ssl,FILE* resource){
    char buffer[8192];  //正文

    fgets(buffer,sizeof(buffer),resource);

    while(!feof(resource)){
        int len = SSL_write(ssl,buffer,strlen(buffer));

        if(len < 0){ //发送body的过程中出现问题
            fprintf(stderr,"send body error. reason: %s\n",strerror(errno));
            break;
        }

        if(debug) fprintf(stdout,"%s",buffer);

        fgets(buffer,sizeof(buffer),resource);
    }
}

// 返回值：-1 表示读取出错， 等于0表示读到一个空行，大于0表示成功读取一行
// 如果一行数据超过了size，那么就会截断
int get_line(SSL* ssl,char *buffer,int size){
    int count = 0;     //读取的字符数
    char ch = '\0';    //读取的字符
    int len = 0;       //SSL_read函数实际读取的长度

    while((count < size - 1) && ch != '\n'){
        len = SSL_read(ssl,&ch,1);
        if(len == 1){
            if(ch == '\r'){
                continue;
            }else if(ch == '\n'){
                break;
            }
            //处理一般字符
            buffer[count] = ch;
            count++;
        }else if( len == -1 ) {     //读取出错
            perror("SSL_read failed");
            count = -1;
            break;  
        }else{                      //SSL_read返回0，表示客户端断开socket连接
            fprintf(stderr,"client close.\n");
            count = -1;
            break;
        }
    }
    if(count >= 0){
        buffer[count] = '\0';
    }
    return count;
}

void not_found(SSL* ssl){
    const char * reply = "404 not found!!!";        //响应正文
    char buffer[1024];                              //响应头
    strcpy(buffer,"HTTP/1.0 404 NOT FOUND\r\n");
    strcat(buffer,"Server: Gao79135 Server\r\n");
    strcat(buffer,"Content-Type: text/html\r\n");
    strcat(buffer,"Connection: Close\r\n\r\n");
    strcat(buffer,reply);
    int len = SSL_write(ssl,buffer,strlen(buffer));
    if(debug) fprintf(stdout,buffer);

    if(len <= 0){
        fprintf(stderr, "send reply failed. reason: %s\n",strerror(errno));
    }
}

void bad_request(SSL* ssl){
    const char * reply = "400 bad request!!!";        //响应正文
    char buffer[1024];                                //响应头
    strcpy(buffer,"HTTP/1.0 400 BAD REQUEST\r\n");
    strcat(buffer,"Server: Gao79135 Server\r\n");
    strcat(buffer,"Content-Type: text/html\r\n");
    strcat(buffer,"Connection: Close\r\n\r\n");
    strcat(buffer,reply);
    int len = SSL_write(ssl,buffer,strlen(buffer));
    if(debug) fprintf(stdout,buffer);

    if(len <= 0){
        fprintf(stderr, "send reply failed. reason: %s\n",strerror(errno));
    }
}

void unimplemented(SSL* ssl){
    const char * reply = "501 method not implemented!!!";   //响应正文
    char buffer[1024];                                      //响应头
    strcpy(buffer,"HTTP/1.0 501 Method NOT IMPLEMENTED\r\n");
    strcat(buffer,"Server: Gao79135 Server\r\n");
    strcat(buffer,"Content-Type: text/html\r\n");
    strcat(buffer,"Connection: Close\r\n\r\n");
    strcat(buffer,reply);
    int len = SSL_write(ssl,buffer,strlen(buffer));
    if(debug) fprintf(stdout,buffer);

    if(len <= 0){
        fprintf(stderr, "send reply failed. reason: %s\n",strerror(errno));
    }
}

void inner_error(SSL* ssl){
    const char * reply = "500 internal server error!!!";//响应正文
    char buffer[1024];                                  //响应头
    strcpy(buffer,"HTTP/1.0 500 Internal Server Error\r\n");
    strcat(buffer,"Server: Gao79135 Server\r\n");
    strcat(buffer,"Content-Type: text/html\r\n");
    strcat(buffer,"Connection: Close\r\n\r\n");
    strcat(buffer,reply);
    int len = SSL_write(ssl,buffer,strlen(buffer));
    if(debug) fprintf(stdout,buffer);

    if(len <= 0){
        fprintf(stderr, "send reply failed. reason: %s\n",strerror(errno));
    }
}

void moved_permanently(int client_socket){
    char buffer[1024];                                                      //响应头
    strcpy(buffer,"HTTP/1.1 301 Moved Permanently\r\n");
    strcat(buffer,"Location: https://192.168.11.137/index.html\r\n\r\n");   
    
    int len = write(client_socket,buffer,strlen(buffer));
    if(debug) fprintf(stdout,buffer);

    if(len <= 0){
        fprintf(stderr, "send reply failed. reason: %s\n",strerror(errno));
    }
}

//start_byte:当前传输的起始字节，end_byte:当前传输的结束字节，total_byte:整个文件的总字节数
void send_video_to_browser(SSL* ssl,FILE* resource){
    unsigned char content[UPLOAD_SIZE];                      //一次上传UPLOAD_SIZE个k
    long start_bytes = 0;
    long end_bytes = 0;
    size_t read_len;
    long video_total_bytes;                                  //代表视频文件的总大小
    char buffer[1024];                                       //响应头
    char content_range[128];                                 //content-range字段
    long content_length;                                     //代表当前响应体的长度

    fseek(resource, 0, SEEK_END);                            //将文件指针移动到末尾
    video_total_bytes = ftell(resource);                     //求得总大小
    fseek(resource, 0, SEEK_SET);                            //将文件指针移动回起始位置


    if(!flag){
        start_bytes = 0;
        end_bytes = UPLOAD_SIZE - 1;
        content_length = end_bytes - start_bytes + 1;
        //返回206状态码
        // 设置Content-Range头
        snprintf(content_range, sizeof(content_range), "bytes %ld-%ld/%ld", start_bytes, end_bytes, video_total_bytes);
        // 设置206 Partial Content响应头
        snprintf(buffer, sizeof(buffer),
                "HTTP/1.1 206 Partial Content\r\n"
                "Content-Range: %s\r\n"
                "Content-Length: %ld\r\n"
                "Content-Type: video/mp4\r\n"
                "\r\n", content_range, content_length);
        int len = SSL_write(ssl,buffer,strlen(buffer));

        if(len <= 0){
            fprintf(stderr,"send reply failed. reason: %s\n",strerror(errno));
        }

        if(debug) fprintf(stdout,buffer);

        flag = 1;
    }else{
        fseek(resource,prev_position,SEEK_SET); 
        start_bytes = ftell(resource);
        read_len = fread(content,1,UPLOAD_SIZE,resource);
        if(read_len == 0){
            prev_position = 0;
            flag = 0;
            return;
        }
        end_bytes = ftell(resource) - 1;
        if(end_bytes > video_total_bytes){
            end_bytes = read_len;
        }

        prev_position = ftell(resource);
        content_length = end_bytes - start_bytes + 1;       //当前响应体的长度


        //返回206状态码
        // 设置Content-Range头
        snprintf(content_range, sizeof(content_range), "bytes %ld-%ld/%ld", start_bytes, end_bytes, video_total_bytes);
        // 设置206 Partial Content响应头
        snprintf(buffer, sizeof(buffer),
                "HTTP/1.1 206 Partial Content\r\n"
                "Content-Range: %s\r\n"
                "Content-Length: %ld\r\n"
                "Content-Type: video/mp4\r\n"
                "\r\n", content_range, content_length);

        if(debug) fprintf(stdout,buffer);

        int len = SSL_write(ssl,buffer,strlen(buffer));

        if(len <= 0){
            fprintf(stderr,"send reply failed. reason: %s\n",strerror(errno));
        }

        len = SSL_write(ssl,content,read_len);
        if(len <= 0){
            fprintf(stderr,"send content failed. reason: %s\n",strerror(errno));
        }

    }
}

void send_video_to_vlc(SSL* ssl,FILE* resource){
    unsigned char content[UPLOAD_SIZE];                      //一次上传UPLOAD_SIZE个k
    long start_bytes = 0;
    long end_bytes = 0;
    size_t read_len;
    long video_total_bytes;                                  //代表视频文件的总大小
    char buffer[1024];                                       //响应头
    char content_range[128];                                 //content-range字段
    long content_length;                                     //代表当前响应体的长度

    fseek(resource, 0, SEEK_END);                            //将文件指针移动到末尾
    video_total_bytes = ftell(resource);                     //求得总大小
    fseek(resource, 0, SEEK_SET);                            //将文件指针移动回起始位置



    //返回200状态码
    snprintf(buffer, sizeof(buffer),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: video/mp4\r\n"
            "\r\n");

    int len = SSL_write(ssl,buffer,strlen(buffer));

    if(len <= 0){
        fprintf(stderr,"send reply failed. reason: %s\n",strerror(errno));
    }

    if(debug) fprintf(stdout,buffer);

    while(1){
        fseek(resource,prev_position,SEEK_SET);
        start_bytes = ftell(resource);
        read_len = fread(content,1,UPLOAD_SIZE,resource);
        if(read_len == 0){
            prev_position = 0;
            return;
        }
        end_bytes = ftell(resource) - 1;

        if(end_bytes > video_total_bytes){
            end_bytes = read_len;
        }

        content_length = end_bytes - start_bytes + 1;
        prev_position = ftell(resource);

        printf("start:%ld end:%ld total:%ld\n",start_bytes,end_bytes,video_total_bytes);

        len = SSL_write(ssl,content,read_len);

        if(len <= 0){
            fprintf(stderr,"send content failed. reason: %s\n",strerror(errno));
        }
    }
}
