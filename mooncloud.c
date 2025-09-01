#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "md5.h"
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>

#define SEG_SIZE   (30*1024*1024)      /* 分片文件大小设置 */
#define BUF        4096

// 全局变量存储 SPS/PPS
#define MAX_PARAM_SIZE 1024
static uint8_t sps[MAX_PARAM_SIZE];
static uint8_t pps[MAX_PARAM_SIZE];
static uint8_t vps[MAX_PARAM_SIZE];
static int sps_len = 0, pps_len = 0, vps_len = 0;
static int header_written = 0;

// NAL单元计数器
static int need_cut = 0;

// 新增变量用于处理双写模式
static FILE *new_fp = NULL;      // 新文件指针
static int double_write = 0;     // 是否处于双写模式
static char new_seg_path[256];   // 新文件路径

// NAL单元类型
typedef struct {
    uint8_t vps;
    uint8_t sps;
    uint8_t pps;
    uint8_t idr;
    uint8_t fu;  
} NalMapEx;

static const NalMapEx nal_tab[2] = {
    /* H.264 */
    { 0, 7, 8, 5, 28},
    /* H.265 */
    {32, 33, 34, 19, 49}
};

static void md5_hex(const char *in, char out[33])
{
    uint8_t md[16];
    MD5(in, strlen(in), md);
    for (int i = 0; i < 16; ++i)
        sprintf(out + 2 * i, "%02x", md[i]);
}


// 写入参数集到文件
static void write_parameters(FILE *file, int codec_idx) {
    static const uint8_t start_code[4] = {0x00, 0x00, 0x00, 0x01};
    
    if (codec_idx == 1 && vps_len > 0) { // H.265需要VPS
        fwrite(start_code, 1, 4, file);
        fwrite(vps, 1, vps_len, file);
    }
    
    if (sps_len > 0) {
        fwrite(start_code, 1, 4, file);
        fwrite(sps, 1, sps_len, file);
    }
    
    if (pps_len > 0) {
        fwrite(start_code, 1, 4, file);
        fwrite(pps, 1, pps_len, file);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <ip[:port]> <user> <pass> <path>\n", argv[0]);
        return 1;
    }

    /* 解析 ip[:port] */
    char host[64]; int port = 554;
    if (sscanf(argv[1], "%63[^:]:%d", host, &port) < 1)
        strcpy(host, argv[1]);
    const char *user = argv[2], *pwd = argv[3], *path = argv[4];

    
    int ctrl = socket(AF_INET, SOCK_STREAM, 0);
    if (ctrl < 0) {
        perror("socket"); return 1;
    }
    
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_aton(host, &sa.sin_addr) == 0) {
        fprintf(stderr, "Invalid IP address\n");
        close(ctrl);
        return 1;
    }
    
    if (connect(ctrl, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect"); 
        close(ctrl);
        return 1;
    }

    
    char buf[BUF], realm[128], nonce[128];

    snprintf(buf, sizeof(buf),
             "DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\n"
             "CSeq: 1\r\nAccept: application/sdp\r\n\r\n",
             host, port, path);
    if (send(ctrl, buf, strlen(buf), 0) < 0) {
        perror("send DESCRIBE");
        close(ctrl);
        return 1;
    }
    
    int n = recv(ctrl, buf, sizeof(buf)-1, 0);
    if (n <= 0) {
        perror("recv DESCRIBE response");
        close(ctrl);
        return 1;
    }
    buf[n] = 0;

    char *auth = strstr(buf, "WWW-Authenticate: Digest");
    if (!auth) {
        fprintf(stderr, "No authentication challenge found\n");
        close(ctrl);
        return 1;
    }
    
    sscanf(auth, "%*[^\"]\"%127[^\"]\"", realm);
    auth = strstr(auth, "nonce=\"");
    if (!auth) {
        fprintf(stderr, "No nonce found in authentication challenge\n");
        close(ctrl);
        return 1;
    }
    sscanf(auth, "nonce=\"%127[^\"]\"", nonce);

   
    char ha1[33], ha2[33], resp[33], tmp[512];
    snprintf(tmp, sizeof(tmp), "%s:%s:%s", user, realm, pwd);
    md5_hex(tmp, ha1);
    snprintf(tmp, sizeof(tmp), "DESCRIBE:%s", path);
    md5_hex(tmp, ha2);
    snprintf(tmp, sizeof(tmp), "%s:%s:%s", ha1, nonce, ha2);
    md5_hex(tmp, resp);


    snprintf(buf, sizeof(buf),
             "DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\n"
             "CSeq: 2\r\nAccept: application/sdp\r\n"
             "Authorization: Digest username=\"%s\", realm=\"%s\", "
             "nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n\r\n",
             host, port, path, user, realm, nonce, path, resp);
    if (send(ctrl, buf, strlen(buf), 0) < 0) {
        perror("send authenticated DESCRIBE");
        close(ctrl);
        return 1;
    }
    
    n = recv(ctrl, buf, sizeof(buf)-1, 0);
    if (n <= 0) {
        perror("recv authenticated DESCRIBE response");
        close(ctrl);
        return 1;
    }
    buf[n] = 0;
    

   
    int codec_idx = -1;

    if (strstr(buf, "a=rtpmap:96 H264/") || strstr(buf, "a=rtpmap:97 H264/")){
        printf("=============是h264===================\n");
        codec_idx = 0;  /* H.264 */
    }
    else if (strstr(buf, "a=rtpmap:96 H265/") || strstr(buf, "a=rtpmap:97 H265/")){
        printf("=============是h265===================\n");
        codec_idx = 1;  /* H.265 */
    }
    else{
        printf("=============失败===================\n");
        codec_idx = 0;  /* 默认按 H.264 处理 */
    }

    /* === 5. 解析 Content-Base: 得到 base_url === */
    char base_url[512] = {0};
    char *cb = strstr(buf, "Content-Base:");
    if (cb) {
        cb += strlen("Content-Base:");
        while (*cb == ' ' || *cb == '\t') ++cb;
        sscanf(cb, "%511[^\r\n]", base_url);
    } else {
        snprintf(base_url, sizeof(base_url), "rtsp://%s:%d%s", host, port, path);
        size_t len = strlen(base_url);
        while (len && base_url[len-1] == '/') base_url[--len] = '\0';
    }

    /* === 6. 取视频轨道的 media-level control URL === */
    char track_url[256] = {0};
    char *m = strstr(buf, "m=video");
    if (m) {
        char *next_m = strstr(m + 1, "m=");
        if (!next_m) next_m = buf + strlen(buf);
        char *c = strstr(m, "a=control:");
        if (c && c < next_m)
            sscanf(c, "a=control:%255s", track_url);
    }

    /* === 7. 拼 SETUP URL === */
    char setup_url[512];
    if (track_url[0] == '/')
        snprintf(setup_url, sizeof(setup_url), "%s%s", base_url, track_url);
    else
        snprintf(setup_url, sizeof(setup_url), "%s/%s", base_url, track_url);
    printf("track_url = %s\n", track_url);
    printf("SETUP URL: %s\n", setup_url);

    /* === 8. 发送 SETUP === */
    snprintf(buf, sizeof(buf),
             "SETUP %s RTSP/1.0\r\n"
             "CSeq: 3\r\n"
             "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
             "Authorization: Digest username=\"%s\", realm=\"%s\", "
             "nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n\r\n",
             setup_url, user, realm, nonce, setup_url, resp);
    if (send(ctrl, buf, strlen(buf), 0) < 0) {
        perror("send SETUP");
        close(ctrl);
        return 1;
    }
    
    n = recv(ctrl, buf, sizeof(buf)-1, 0);
    if (n <= 0) {
        perror("recv SETUP response");
        close(ctrl);
        return 1;
    }
    buf[n] = 0;

    char session[64] = {0};
    char *s = strstr(buf, "Session:");
    if (s) sscanf(s, "Session: %63[^;\r\n]", session);
    printf("=== SETUP response ===\n%s\n", buf);

    /* === 9. PLAY === */
    snprintf(buf, sizeof(buf),
             "PLAY rtsp://%s:%d%s/ RTSP/1.0\r\n"
             "CSeq: 4\r\nSession: %s\r\n"
             "Authorization: Digest username=\"%s\", realm=\"%s\", "
             "nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n\r\n",
             host, port, path, session,
             user, realm, nonce, setup_url, resp);
    if (send(ctrl, buf, strlen(buf), 0) < 0) {
        perror("send PLAY");
        close(ctrl);
        return 1;
    }
    
    n = recv(ctrl, buf, sizeof(buf)-1, 0);
    if (n <= 0) {
        perror("recv PLAY response");
        close(ctrl);
        return 1;
    }
    buf[n] = 0;
    printf("=== PLAY response ===\n%s\n", buf);

  

 
    const char *dir = ".";   /* 当前目录 */
    

    /* 时间戳文件名生成 */
    char seg_path[256];
    time_t     now;
    struct tm *tm_now;


    size_t seg_len = 0;
    FILE  *fp      = NULL;
    

    /* 先打开第一个片段 */
    now     = time(NULL);
    tm_now  = localtime(&now);
    const char *ext = (codec_idx == 0) ? "h264" : "h265";
    snprintf(seg_path, sizeof(seg_path),
            "%s/%04d%02d%02d_%02d%02d%02d.%s",
            dir,
            tm_now->tm_year + 1900,
            tm_now->tm_mon + 1,
            tm_now->tm_mday,
            tm_now->tm_hour,
            tm_now->tm_min,
            tm_now->tm_sec,
            ext);
    fp = fopen(seg_path, "wb");
    if (!fp) { 
        perror("fopen"); 
        close(ctrl);
        return 1; 
    }

    printf("开始录制，片段保存到 %s/\n", dir);

    header_written = 0;
    sps_len = 0;
    pps_len = 0;
    vps_len = 0;
    uint8_t hdr_buf[4];

    printf("开始接收视频流...\n");
    
    // 预分配缓冲区以避免频繁malloc/free
    uint8_t *rtp_buf = malloc(65536);
    if (!rtp_buf) {
        fprintf(stderr, "内存分配失败\n");
        fclose(fp);
        close(ctrl);
        return 1;
    }
    
    // 起始码定义
    static const uint8_t start_code[4] = {0x00, 0x00, 0x00, 0x01};

    for (;;) {
        uint8_t ch;
        while (1) {
            ssize_t r = recv(ctrl, &ch, 1, 0);
            if (r <= 0) { perror("sync"); goto out; }
            if (ch == '$') {
                ssize_t r = recv(ctrl, &ch, 1, 0);
                if (r <= 0) { perror("sync"); goto out; }
                if (ch == 0) {
                    break;
                }
            }
        }
        
        hdr_buf[0] = '$';
        hdr_buf[1] = 0; 
        ssize_t received = recv(ctrl, hdr_buf + 2, 2, MSG_WAITALL);
        if (received != 2) {
            if (received == 0) {
                fprintf(stderr, "Connection closed while reading RTP header\n");
            } else {
                perror("read RTP header tail");
            }
            goto out;
        }
        
        uint16_t pkt_len = (hdr_buf[2] << 8) | hdr_buf[3];
        uint8_t ch_id = hdr_buf[1];

        if (ch_id != 0 || pkt_len == 0 || pkt_len > 65536 - 4) {
            fprintf(stderr, "Bad RTP header: ch %d, len %u\n", ch_id, pkt_len);
            continue;
        }
        
        // 复制头信息
        memcpy(rtp_buf, hdr_buf, 4);
        
        // 读 RTP 包内容
        received = recv(ctrl, rtp_buf + 4, pkt_len, MSG_WAITALL);
        if (received != pkt_len) {
            if (received == 0) {
                fprintf(stderr, "Connection closed while reading RTP payload\n");
            } else {
                fprintf(stderr, "Incomplete RTP packet: expected %d, got %zd\n", pkt_len, received);
            }
            goto out;
        }
        
        // 跳过 RTP-over-TCP 头(4字节)和 RTP 头(12字节)
        const uint8_t *payload = rtp_buf + 4 + 12;
        size_t payload_size = pkt_len - 12;

        if (payload_size < 1) {
            continue;
        }
        
        // 判断NAL类型
        uint8_t nal_type;
        uint8_t fu_start = 0, fu_end = 0;
        uint8_t is_fu = 0;
        
        if (codec_idx == 0) { // H.264
            if ((payload[0] & 0x1F) == nal_tab[codec_idx].fu) { // FU-A 分片
                is_fu = 1;
                nal_type = payload[1] & 0x1F; // 从FU头获取真实NAL类型
                fu_start = (payload[1] & 0x80) != 0;
                fu_end = (payload[1] & 0x40) != 0;
            } else {
                nal_type = payload[0] & 0x1F;
            }
        } else { // H.265
            uint8_t nal_unit_type = (payload[0] >> 1) & 0x3F;
            if (nal_unit_type == nal_tab[codec_idx].fu) { // FU
                is_fu = 1;
                fu_start = (payload[2] & 0x80) != 0; // 第7位是起始标志
                fu_end = (payload[2] & 0x40) != 0;   // 第6位是结束标志
                nal_type = payload[2] & 0x3F;        // 低6位是NAL类型
            } else {
                nal_type = nal_unit_type;
            }
        }
      

        // 提取 SPS/PPS/VPS (无论是否已经存在，都更新)
        if (nal_type == nal_tab[codec_idx].sps) {
            memset(sps, 0, sizeof(sps));
            memcpy(sps, payload, payload_size);
            sps_len = payload_size;
            printf("SPS, len=%d\n", sps_len);
        } 
        else if (nal_type == nal_tab[codec_idx].pps) {
            memset(pps, 0, sizeof(pps));
            memcpy(pps, payload, payload_size);
            pps_len = payload_size;
            printf("PPS, len=%d\n", pps_len);
        }
        else if (codec_idx == 1 && nal_type == nal_tab[codec_idx].vps) {
            memset(vps, 0, sizeof(vps));
            memcpy(vps, payload, payload_size);
            vps_len = payload_size;
            printf("VPS, len=%d\n", vps_len);
        }
        
        // 检查是否已准备好写入数据（有完整的参数集）
        int ready = (codec_idx == 0) ? (sps_len && pps_len) : (vps_len && sps_len && pps_len);
        
        // 在开始写入视频数据前，先写入 VPS/SPS/PPS
        if (ready && !header_written) {
            write_parameters(fp, codec_idx);
            header_written = 1;
            seg_len = ftell(fp);
            printf("Wrote VPS/SPS/PPS to file\n");
        }
        
        // 处理 FU-A 分片
        if (is_fu) {
            // 如果是IDR帧的FU-start且需要切割，开启双写模式
            if (need_cut && nal_type == nal_tab[codec_idx].idr && fu_start && !double_write) {
                printf("IDR FU-start detected, starting double write mode\n");
                
                // 创建新文件
                now = time(NULL);
                tm_now = localtime(&now);
                snprintf(new_seg_path, sizeof(new_seg_path),
                        "%s/%04d%02d%02d_%02d%02d%02d.%s",
                        dir,
                        tm_now->tm_year + 1900,
                        tm_now->tm_mon + 1,
                        tm_now->tm_mday,
                        tm_now->tm_hour,
                        tm_now->tm_min,
                        tm_now->tm_sec,
                        ext);
                
                new_fp = fopen(new_seg_path, "wb");
                if (!new_fp) {
                    perror("fopen新文件失败");
                    double_write = 0;
                } else {
                    // 写入参数集到新文件
                    write_parameters(new_fp, codec_idx);
                    double_write = 1;
                    printf("开始双写模式，新文件: %s\n", new_seg_path);
                }
            }
            
            // 写入数据到当前文件
            if (fu_start) {
                // FU-Start: 写入起始码 + 重组NAL头 + 数据
                fwrite(start_code, 1, 4, fp);
                
                // 重组 NAL 头
                
                if (codec_idx == 0) {
                    uint8_t reconstructed_nal_header;
                    reconstructed_nal_header = (payload[0] & 0xE0) | nal_type;
                    fwrite(&reconstructed_nal_header, 1, 1, fp);
                    fwrite(payload + 2, 1, payload_size - 2, fp);
                } else {
                    // H.265 处理
                    uint8_t byte0 = (payload[0] & 0x81) | (nal_type << 1);
                    uint8_t byte1 = payload[1];
                    
                    fwrite(&byte0, 1, 1, fp);
                    fwrite(&byte1, 1, 1, fp);
                    
                    // 写入FU载荷（跳过前3个字节：2字节NAL头 + 1字节FU头）
                    fwrite(payload + 3, 1, payload_size - 3, fp);
                }
            } else {
                // FU-Middle 或 FU-End: 只写入数据部分
                if (codec_idx == 0) {
                    fwrite(payload + 2, 1, payload_size - 2, fp);
                } else {
                    fwrite(payload + 3, 1, payload_size - 3, fp);
                }
            }
            
            // 如果处于双写模式，同时写入新文件
            if (double_write && new_fp) {
                if (fu_start) {
                    fwrite(start_code, 1, 4, new_fp);
                    
                    uint8_t reconstructed_nal_header;
                    if (codec_idx == 0) {
                        reconstructed_nal_header = (payload[0] & 0xE0) | nal_type;
                        fwrite(&reconstructed_nal_header, 1, 1, new_fp);
                        fwrite(payload + 2, 1, payload_size - 2, new_fp);
                    } else {
                        uint8_t byte0 = (payload[0] & 0x81) | (nal_type << 1);
                        uint8_t byte1 = payload[1];
                        
                        fwrite(&byte0, 1, 1, new_fp);
                        fwrite(&byte1, 1, 1, new_fp);
                        fwrite(payload + 3, 1, payload_size - 3, new_fp);
                    }
                } else {
                    if (codec_idx == 0) {
                        fwrite(payload + 2, 1, payload_size - 2, new_fp);
                    } else {
                        fwrite(payload + 3, 1, payload_size - 3, new_fp);
                    }
                }
            }
            
            seg_len = ftell(fp);
            
            // 检查是否需要切割（文件大小达到阈值）
            if (seg_len >= SEG_SIZE && !double_write) {
                need_cut = 1;
            }
            
            // 如果是IDR帧的FU-end且处于双写模式，结束双写模式
            if (double_write && fu_end && nal_type == nal_tab[codec_idx].idr) {
                printf("IDR FU-end detected, ending double write mode\n");
                fclose(fp);
                char cmd[512];
                snprintf(cmd, sizeof(cmd), "bash cloud.sh %s", seg_path);
                int rc = system(cmd);
                if (rc == -1) {
                    perror("system(cloud.sh)");
                }
                printf("片段写完：%s (大小: %zu bytes)\n", seg_path, seg_len);
                
                // 切换到新文件
                fp = new_fp;
                strcpy(seg_path, new_seg_path);
                new_fp = NULL;
                double_write = 0;
                need_cut = 0;
                
                seg_len = ftell(fp);
                printf("切换到新片段: %s\n", seg_path);
            }
            
            continue;
        }

        // 处理普通 NAL 单元
        if (header_written) {
            fwrite(start_code, 1, 4, fp);
            fwrite(payload, 1, payload_size, fp);
            seg_len = ftell(fp);
            
            // 检查是否需要切割（文件大小达到阈值）
            if (seg_len >= SEG_SIZE && !double_write) {
                need_cut = 1;
            }
            
            // 如果是IDR帧且需要切割，创建新文件
            if (need_cut && nal_type == nal_tab[codec_idx].idr) {
                fclose(fp);
                char cmd[512];
                snprintf(cmd, sizeof(cmd), "bash cloud.sh %s", seg_path);
                int rc = system(cmd);
                if (rc == -1) {
                    perror("system(cloud.sh)");
                }
                printf("普通 NAL 单元片段写完：%s (大小: %zu bytes)\n", seg_path, seg_len);
                
                // 创建新文件
                now = time(NULL);
                tm_now = localtime(&now);
                snprintf(seg_path, sizeof(seg_path),
                        "%s/%04d%02d%02d_%02d%02d%02d.%s",
                        dir,
                        tm_now->tm_year + 1900,
                        tm_now->tm_mon + 1,
                        tm_now->tm_mday,
                        tm_now->tm_hour,
                        tm_now->tm_min,
                        tm_now->tm_sec,
                        ext);
                        
                fp = fopen(seg_path, "wb");
                if (!fp) {
                    perror("fopen新文件失败");
                    break;
                }
                
               
                write_parameters(fp, codec_idx);
                
               
                fwrite(start_code, 1, 4, fp);
                fwrite(payload, 1, payload_size, fp);
                
                seg_len = ftell(fp);
                need_cut = 0;
                printf("创建新片段: %s\n", seg_path);
            }
        }
    }

out:
    free(rtp_buf);
    if (fp) fclose(fp);
    if (new_fp) fclose(new_fp);
    printf("录制结束\n");
    close(ctrl);
    return 0;
}