#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include  <signal.h>
#include <errno.h>
#include <pthread.h>

#define MAXLINE 			4096 /*max text line length*/
#define LISTENQ 			200	 /*maximum number of client connections*/
#define ROOT				"./www/"
#define GET_METHOD	 		"GET"
#define VERSION_0 			"HTTP/1.0"
#define VERSION_1 			"HTTP/1.1"
#define CRLF 				"\r\n"

int serverfd = -1;

void INThandler(int);
int command_handler(int socketfd, char buf[]);

/**
 * Method: 	main
 * Sources: https://www.cs.dartmouth.edu/~campbell/cs50/socketprogramming.html
 * Uses: 	Recieve connection requests
 * 			Fork for every connection
 * 			Parse connections
 */
int main(int argc, char **argv)
{
	int listenfd, connfd, n;
	pid_t childpid;
	socklen_t clilen;
	int portno;
	char buf[MAXLINE];
	struct sockaddr_in cliaddr, servaddr;

	if (argc != 2)
	{
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
	}
	portno = atoi(argv[1]);

	signal(SIGINT, INThandler);

	// Create a socket for the soclet
	// If sockfd<0 there was an error in the creation of the socket
	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("Problem in creating the socket");
		exit(2);
	}
	serverfd = listenfd;

	// preparation of the socket address
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(portno);

	// bind the socket
	bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr));

	// listen to the socket by creating a connection queue, then wait for clients
	listen(listenfd, LISTENQ);

	printf("%s\n", "Server running...waiting for connections.");

	while (1)
	{
		clilen = sizeof(cliaddr);
		// accept a connection
		connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
		int iskeepalive = 0;

		printf("%s\n", "Received request...");

		if ((childpid = fork()) == 0)
		{ // if it’s 0, it’s child process

			printf("%s\n", "Child created for dealing with client requests");

			// close listening socket
			close(listenfd);

			while ((n = recv(connfd, buf, MAXLINE, 0)) > 0)
			{
				printf("String received from the client: ");
				puts(buf);
				iskeepalive = command_handler(connfd, buf);
				bzero(buf, sizeof(buf));
			}

			if (n < 0)
				printf("%s\n", "Read error");
			
			exit(0);
		}
		if(!iskeepalive) {
			close(connfd);
			printf("Closed connfd\n");
		}
	}
}

void *watchdog_timer(void *arg) {
    sleep(10);  // 10 second
    printf("Child processes took too long to terminate\n");
	close(serverfd);
    printf("Server socket closed.\n");
	return NULL;
}

/**
 * INThandler
 * Sources: https://stackoverflow.com/questions/4217037/catch-ctrl-c-in-c
 * Use: 	Handle CTRL C gracefully
 */
void  INThandler(int sig)
{
    signal(sig, SIG_IGN);
	printf("\nServer exiting...\n");
	pthread_t timer_thread;

	if (serverfd != -1) {
		pthread_create(&timer_thread, NULL, watchdog_timer, NULL); // start timer
		while (wait(NULL)>0) {} 	// wait for child processes to terminate
        close(serverfd);
        printf("Server socket closed.\n");
		pthread_cancel(timer_thread);	// end timer
    }
	 exit(0);
}

/**
 * get_filename_ext
 * Sources: https://stackoverflow.com/questions/5309471/getting-file-extension-in-c
 * Use:		Get the file extension
 */
const char *get_filename_ext(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if(!dot || dot == filename) return "";
    return dot + 1;
}

/********************** REQUEST HEADER FORMAT **********************
 * HTTP/1.1 200 OK \r\n
 * Content-Type: <> \r\n # Tells about the type of content and the formatting of <file contents> 
 * Content-Length:<> \r\n # Numeric value of the number of bytes of <file contents>
 * \r\n<file contents>
*******************************************************************/

/**
 * Method:	command_handler
 * Uses:	Send requested data and header
 */
int command_handler(int connfd, char* buf) {
	// User input buffers
	char method[12];
	char uri[256];
	char version[12];
	int iskeepalive = 0;
	char ka_buf[12];

	// Send buffers
	char filepath[512];
	char contenttype[24];
	char header[256];

    // Parse request from client
    sscanf(buf, "%s %s %s", method, uri, version);

	// check keep alive
	char* p_ka = strstr(buf, "Connection: ");
	if (p_ka == NULL) {
		printf("Connection string not found\n");
		strcpy(ka_buf, "Close");
	} else if (!strncmp(p_ka+12, "Close", 5)){
		printf("Close activated\n");
		strcpy(ka_buf, "Close");
	} else if (!strncmp(p_ka+12, "Keep-alive",10)) {
		iskeepalive = 1;
		strcpy(ka_buf, "Keep-alive");
		printf("Keep alive activated!\n");
	} else {
		char* response = "400 Bad Request\r\nConnection: Close\r\n\r\n";
		send(connfd, response, strlen(response), 0);
		return iskeepalive;
	}

	// Error if not using GET
	if (strcmp(method, GET_METHOD)) {
		sprintf(header, "405 Method Not Allowed\r\nConnection: %s\r\n\r\n", ka_buf);
		send(connfd, header, strlen(header), 0);
		return iskeepalive;
	}

	// Error if wrong versions
	if ((strcmp(version, VERSION_0) != 0) && (strcmp(version, VERSION_1) != 0)) {
		sprintf(header, "505 HTTP Version Not Supported\r\nConnection: %s\r\n\r\n", ka_buf);
		send(connfd, header, strlen(header), 0);
		return iskeepalive;
	}

	// Direct to index.html
	if (strcmp(uri, "/") == 0) {
		strcpy(uri, "index.html");
	}

	// Create file path
	strcpy(filepath, ROOT);
    strcat(filepath, uri);

    // Open file and send response
    int fd = open(filepath, O_RDONLY);
	printf("%s\n", filepath);

    if (fd == -1) { // File not found
		if (errno == EACCES) {
            printf("Permission denied\n");
			sprintf(header, "403 Forbidden\r\nConnection: %s\r\n\r\n", ka_buf);
        } else {
            printf("Error opening file\n");
			sprintf(header, "HTTP/1.1 404 Not Found\r\nConnection: %s\r\n\r\n", ka_buf);
        }
		send(connfd, header, strlen(header), 0);
		if (!iskeepalive) close(connfd);
    }
	else { 			// File found
		// Get file extension type
		const char* ext = get_filename_ext(uri);
		if (strcmp(ext, "html") == 0) {
			strcpy(contenttype,"text/html");
		} else if (strcmp(ext, "txt") == 0) {
			strcpy(contenttype,"text/plain");
		} else if (strcmp(ext, "png") == 0) {
			strcpy(contenttype,"image/png");
		} else if (strcmp(ext, "gif") == 0) {
			strcpy(contenttype,"image/gif");
		} else if (strcmp(ext, "jpg") == 0) {
			strcpy(contenttype,"image/jpg");
		} else if (strcmp(ext, "ico") == 0) {
			strcpy(contenttype,"image/x-icon");
		} else if (strcmp(ext, "css") == 0) {
			strcpy(contenttype,"text/css");
		} else if (strcmp(ext, "js") == 0) {
			strcpy(contenttype,"application/javascript");
		} else {
			sprintf(header, "400 Bad Request\r\nConnection: %s\r\n\r\n", ka_buf);
			send(connfd, header, strlen(header), 0);
			return iskeepalive;
		}

		// Get file size
		ssize_t filesize = lseek(fd, 0, SEEK_END);
		if (filesize == -1) {
			perror("Failed to determine file size");
			close(fd);
			sprintf(header, "400 Bad Request\r\nConnection: %s\r\n\r\n", ka_buf);
			send(connfd, header, strlen(header), 0);
			// if (!iskeepalive) close(connfd);
			return iskeepalive;
		}
	
		// Set file pointer to beginning
		if (lseek(fd, 0, SEEK_SET) == -1) {
			perror("Failed to reset file pointer");
			close(fd);
			sprintf(header, "400 Bad Request\r\nConnection: %s\r\n\r\n", ka_buf);
			send(connfd, header, strlen(header), 0);
			return iskeepalive;
		}
	
		// Create header and get header length
		sprintf(header, "%s 200 OK\r\nContent-Length: %zd\r\nContent-Type: %s\r\nConnection: %s\r\n\r\n",
				version, filesize, contenttype, ka_buf);
		size_t header_len = strlen(header);

		// Allocate memory for the file content + null terminator + header length
		char* resp_buf = (char*)malloc(filesize + 1 + header_len);
		if (!resp_buf) {
			perror("Memory allocation failed");
			close(fd);
			sprintf(header, "400 Bad Request\r\nConnection: %s\r\n\r\n", ka_buf);
			send(connfd, header, strlen(header), 0);
			return iskeepalive;
		}

		memcpy(resp_buf, header, header_len);

		pread(fd, resp_buf+header_len, filesize + 1, 0);
		send(connfd, resp_buf, header_len + filesize + 1, 0);
		free(resp_buf);
    }

	close(fd);
	return iskeepalive;
}
