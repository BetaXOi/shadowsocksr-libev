#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "http_simple.h"
#include "obfsutil.h"

static char* g_useragent[] = {
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
    "Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
    "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
};

static int g_useragent_index = -1;

typedef struct http_simple_local_data {
    int has_sent_header;
    int has_recv_header;
    char *encode_buffer;
}http_simple_local_data;

typedef struct http_simple_global_data {
    int count;
    char *default_host;
    char* payload[16];
} http_simple_global_data;

void* http_simple_init_data() {
    int len = sizeof(http_simple_global_data);
    http_simple_global_data *global = (http_simple_global_data *)malloc(len);
    memset(global, 0, sizeof(len));
    return global;
}

void http_simple_set_server_info(obfs *self, server_info *server) {
    http_simple_global_data *global = (http_simple_global_data *)server->g_data;
    if (global->default_host == NULL) {
        if (server->port == 80)
            asprintf(&global->default_host, "%s", server->host);
        else
            asprintf(&global->default_host, "%s:%u", server->host, server->port);

        // trans
        char *buffer = (char *)malloc(strlen(server->param));
        char *src, *dst;
        src = server->param;
        dst = buffer;
        for (src = server->param, dst = buffer; *src; src++, dst++) {
            if (*src == '\\') {
                switch(*(src + 1)){
                case 'r':
                    *dst = '\r';
                    break;
                case 'n':
                    *dst = '\n';
                    break;
                case 't':
                    *dst = '\t';
                    break;
                default:
                    *dst = *(dst + 1);
                }
                src++;
            } else {
                *dst = *src;
            }
        }

        // parse
        int count;
        char *str = NULL, *token = NULL, *saveptr = NULL;
        for (count = 0, str = buffer; ; count++, str = NULL) {
            token = strtok_r(str, ",", &saveptr);
            if (token == NULL)
                break;
            
            char *payload = (char *)malloc(strlen(token) + 64);
            payload[0] = 0;

            int i;
            char *str, *saveptr;
            for (i = 0, str = token; ; i++, str = NULL) {
                token = strtok_r(str, "#", &saveptr);
                if (token == NULL)
                    break;

                if (i == 0) {
                    char *p = strchr(token, ':');
                    if (p && atoi(p + 1) == 80)
                        *p = 0;
                    strcat(payload, "Host: ");
                    strcat(payload, token);
                    strcat(payload, "\r\n");
                    continue;
                }

                char *str, *saveptr;
                for (str = token; ; str = NULL) {
                    token = strtok_r(str, "\r\n", &saveptr);
                    if (token == NULL)
                        break;
                    
                    strcat(payload, token);
                    strcat(payload, "\r\n");
                }
            }
            
            global->payload[count] = strdup(payload);
            free(payload);
        }
        global->count = count;

        free(buffer);
    }

    memmove(&self->server, server, sizeof(server_info));
}

void http_simple_local_data_init(http_simple_local_data* local) {
    local->has_sent_header = 0;
    local->has_recv_header = 0;
    local->encode_buffer = NULL;

    if (g_useragent_index == -1) {
        g_useragent_index = xorshift128plus() % (sizeof(g_useragent) / sizeof(*g_useragent));
    }
}

obfs * http_simple_new_obfs() {
    obfs * self = new_obfs();
    self->l_data = malloc(sizeof(http_simple_local_data));
    http_simple_local_data_init((http_simple_local_data*)self->l_data);
    return self;
}

void http_simple_dispose(obfs *self) {
    http_simple_local_data *local = (http_simple_local_data*)self->l_data;
    if (local->encode_buffer != NULL) {
        free(local->encode_buffer);
        local->encode_buffer = NULL;
    }
    free(local);
    dispose_obfs(self);
}

char http_simple_hex(char c) {
    if (c < 10) return c + '0';
    return c - 10 + 'a';
}

void http_simple_encode_head(http_simple_local_data *local, char *data, int datalength) {
    if (local->encode_buffer == NULL) {
        local->encode_buffer = (char*)malloc((size_t)(datalength * 3 + 1));
    }
    int pos = 0;
    for (; pos < datalength; ++pos) {
        local->encode_buffer[pos * 3] = '%';
        local->encode_buffer[pos * 3 + 1] = http_simple_hex(((unsigned char)data[pos] >> 4));
        local->encode_buffer[pos * 3 + 2] = http_simple_hex(data[pos] & 0xF);
    }
    local->encode_buffer[pos * 3] = 0;
}

int http_simple_client_encode(obfs *self, char **pencryptdata, int datalength, size_t* capacity) {
    char *encryptdata = *pencryptdata;
    http_simple_local_data *local = (http_simple_local_data*)self->l_data;
    if (local->has_sent_header) {
        return datalength;
    }

    int head_size = self->server.head_len + (int)(xorshift128plus() & 0x3F);
    int outlength;
    char * out_buffer = (char*)malloc((size_t)(datalength + 2048));
    if (head_size > datalength)
        head_size = datalength;
    http_simple_encode_head(local, encryptdata, head_size);;

    http_simple_global_data *global = (http_simple_global_data *)self->server.g_data;
    if (global->count) {
        int idx = (int)(xorshift128plus() % (uint64_t)global->count);

        sprintf(out_buffer,
            "GET /%s HTTP/1.1\r\n"
            "%s"
            "\r\n",
            local->encode_buffer,
            global->payload[idx]);
    } else {
        sprintf(out_buffer,
            "GET /%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.8\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "DNT: 1\r\n"
            "Connection: keep-alive\r\n"
            "\r\n",
            local->encode_buffer,
            global->default_host,
            g_useragent[g_useragent_index]);
    }
    //LOGI("http header: %s", out_buffer);
    outlength = (int)strlen(out_buffer);
    memmove(out_buffer + outlength, encryptdata + head_size, datalength - head_size);
    outlength += datalength - head_size;
    local->has_sent_header = 1;
    if ((int)*capacity < outlength) {
        *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (size_t)(outlength * 2));
        encryptdata = *pencryptdata;
    }
    memmove(encryptdata, out_buffer, outlength);
    free(out_buffer);
    if (local->encode_buffer != NULL) {
        free(local->encode_buffer);
        local->encode_buffer = NULL;
    }
    return outlength;
}

int http_simple_client_decode(obfs *self, char **pencryptdata, int datalength, size_t* capacity, int *needsendback) {
    char *encryptdata = *pencryptdata;
    http_simple_local_data *local = (http_simple_local_data*)self->l_data;
    *needsendback = 0;
    if (local->has_recv_header) {
        return datalength;
    }
    char* data_begin = strstr(encryptdata, "\r\n\r\n");
    if (data_begin) {
        int outlength;
        data_begin += 4;
        local->has_recv_header = 1;
        outlength = datalength - (int)(data_begin - encryptdata);
        memmove(encryptdata, data_begin, outlength);
        return outlength;
    } else {
        return 0;
    }
}

void boundary(char result[])
{
    char *str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    int i,lstr;
    char ss[3] = {0};
    lstr = (int)strlen(str);
    srand((unsigned int)time((time_t *)NULL));
    for(i = 0; i < 32; ++i)
    {
        sprintf(ss, "%c", str[(rand()%lstr)]);
        strcat(result, ss);
    }
}

int http_post_client_encode(obfs *self, char **pencryptdata, int datalength, size_t* capacity) {
    char *encryptdata = *pencryptdata;
    http_simple_local_data *local = (http_simple_local_data*)self->l_data;
    if (local->has_sent_header) {
        return datalength;
    }

    int head_size = self->server.head_len + (int)(xorshift128plus() & 0x3F);
    int outlength;
    char * out_buffer = (char*)malloc((size_t)(datalength + 4096));
    if (head_size > datalength)
        head_size = datalength;
    http_simple_encode_head(local, encryptdata, head_size);

    http_simple_global_data *global = (http_simple_global_data *)self->server.g_data;
    if (global->count) {
        int idx = (int)(xorshift128plus() % (uint64_t)global->count);

        sprintf(out_buffer,
            "POST /%s HTTP/1.1\r\n"
            "%s"
            "\r\n",
            local->encode_buffer,
            global->payload[idx]);
    } else {
        sprintf(out_buffer,
            "POST /%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.8\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "DNT: 1\r\n"
            "Connection: keep-alive\r\n"
            "\r\n",
            local->encode_buffer,
            global->default_host,
            g_useragent[g_useragent_index]);
    }
    //LOGI("http header: %s", out_buffer);
    outlength = (int)strlen(out_buffer);
    memmove(out_buffer + outlength, encryptdata + head_size, datalength - head_size);
    outlength += datalength - head_size;
    local->has_sent_header = 1;
    if ((int)*capacity < outlength) {
        *pencryptdata = (char*)realloc(*pencryptdata, *capacity = (size_t)(outlength * 2));
        encryptdata = *pencryptdata;
    }
    memmove(encryptdata, out_buffer, outlength);
    free(out_buffer);
    if (local->encode_buffer != NULL) {
        free(local->encode_buffer);
        local->encode_buffer = NULL;
    }
    return outlength;
}
