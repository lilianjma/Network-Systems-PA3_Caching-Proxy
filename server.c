#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <openssl/md5.h>
#include <netdb.h>
#include <time.h>
#include <dirent.h>
#include <pthread.h>

#define MAXLINE 			4096 /*max text line length*/
#define LISTENQ 			200	 /*maximum number of client connections*/
#define CACHE				"./cache/"
#define GET_METHOD	 		"GET"
#define VERSION_0 			"HTTP/1.0"
#define VERSION_1 			"HTTP/1.1"
#define CRLF 				"\r\n"
#define BUF_SIZE			64*1024

// LilianTODO: figure out why nothing in the file created
int serverfd = -1;
int timeout_value;

typedef struct {
	char full_url[256];
    char protocol[8];  // http or https
    char host[256];
    int port;
    char page[1024];
} ParsedURL;

// typedef struct { TODOD
// 	 char hash[33]; // MD5 hash returns in hexadecimal
// 	 char timestamp[33]; // max of time_t is 8 bytes + null
// } CachedFile;


void INThandler(int);
int client_handler(int clientfd, char* buf);

int parse_request(char* buf, char* header, ParsedURL* url);// Works
void get_hash_str(char* str, char* hash_str);	// Works
int in_cache(char* hash_str);	// Works
int add_file_to_cache(int clientfd, char* buf, ParsedURL* url, char* file_hash);
int send_file(int clientfd, char* filename);	// Works

/**
 * Method: 	main
 * Sources: https://www.cs.dartmouth.edu/~campbell/cs50/socketprogramming.html
 * Uses: 	Recieve connection requests
 * 			Fork for every connection
 * 			Parse connections
 */
int main(int argc, char **argv)
{
	int listenfd, clientfd, n;
	pid_t childpid;
	socklen_t clilen;
	int portno;
	char buf[MAXLINE];
	struct sockaddr_in cliaddr, servaddr;

	// Make sure input is right
	if (argc == 3) {
		portno = atoi(argv[1]);
		timeout_value = atoi(argv[2]);
	} else {
		fprintf(stderr, "usage: %s <port> <timeout_value>\n", argv[0]);
		exit(1);
	}

	// CTRL+C handler
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
		// accept a connection
		clilen = sizeof(cliaddr);
		clientfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
		printf("%s\n", "Received request...");
		if (clientfd < 0) {
            printf("Accept failed");
            continue;
        }

		if ( (childpid = fork()) == 0) { // if it’s 0, it’s child process
			printf("%s\n", "Child created for dealing with client requests");
			close(listenfd); // child doesn't need listening socket

			while ((n = recv(clientfd, buf, MAXLINE, 0)) > 0) {
				printf("~~~~ String received from the client: "); puts(buf);
				client_handler(clientfd, buf);
				bzero(buf, sizeof(buf));
			}

			if (n < 0)
				printf("%s\n", "Read error");
			
			exit(0);
		} else if (childpid > 0) {
            close(clientfd);
        } else {
            printf("Fork failed");
        }
	}
}

/**
 * Method:	command_handler
 * Uses:	Send requested data and header
 */
int client_handler(int clientfd, char* buf) {
	// Buffers
	char header[256];
	char filename[128];
	char file_hash[33];
	ParsedURL url;
	
	// Parse request
	if (parse_request(buf, header, &url) == EXIT_FAILURE) {
		send(clientfd, header, strlen(header), 0);
		return -1;
	}
	
	// Create filename from host and page
	strcpy(filename, url.host);
	strcat(filename, url.page);

	// Get file hash
	get_hash_str(filename, file_hash);

	// Check if file exists in cache
	if (!in_cache(file_hash)) {
		add_file_to_cache(clientfd, buf, &url, file_hash);
	}

	send_file(clientfd, file_hash);
	
	return 0;
}

/**
 * parse_url
 * Sources: https://stackoverflow.com/questions/726122/best-ways-of-parsing-a-url-using-c
 * Use: split url into protocol, host, port number, and page path
 * Returns: -1 on fail, 0 on success
 */
int parse_url(const char *url, ParsedURL *result) {
	int n;
	result->port = 80;
	strcpy(result->page, "");
	if ( (n = sscanf(url, "%7[^:]://%255[^:/]:%d/%1023[^\0]", result->protocol, result->host, &result->port, result->page)) < 3) {
		if ((n = sscanf(url, "%7[^:]://%255[^//]/%1023[^\0]", result->protocol, result->host, result->page)) < 2) {
			return -1;
		}
	}
    return 0;
}

/**
 * parse the url from buf, store into parsed_url
 */
int parse_request(char* buf, char* header, ParsedURL* parsed_url) {
	char method[12];
	char url[256];
	char version[12];

    // Parse request from client
    sscanf(buf, "%s %s %s", method, url, version);
	strcpy(parsed_url->full_url, url);

	// Error if not using GET
	if (strcmp(method, GET_METHOD)) {
		sprintf(header, "400 Bad Request\r\n\r\n");
		return EXIT_FAILURE;
	}

	// Error if wrong versions
	if ((strcmp(version, VERSION_0) != 0) && (strcmp(version, VERSION_1) != 0)) {
		sprintf(header, "505 HTTP Version Not Supported\r\n\r\n");
		return EXIT_FAILURE;
	}

	// Error if url unable to be parsed into host, portno, page
	if (parse_url(url, parsed_url) == -1) {
		printf("ERROR: Url not able to be parsed\n");
		sprintf(header, "400 Bad Request\r\n\r\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/**
 * Source: https://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c
 * hash_str must be 33 bytes long
 */
void get_hash_str(char* str, char* hash_str){
	unsigned char md5[16];
	MD5_CTX context;
	MD5_Init(&context);
	MD5_Update(&context, str, strlen(str));
	MD5_Final(md5, &context);
  
	for(int i = 0; i < 16; ++i){
	  sprintf(hash_str+i*2, "%02x", (unsigned int)md5[i]);
	}
	hash_str[32] = '\0';
	printf("Hash: %s to %s\n", str, hash_str);
}  

int in_cache(char* hash_str) {
	printf("in_cache\n");

	DIR *dir = opendir(CACHE);
    if (dir == NULL) {
        perror("Failed to open directory");
        return -1;
    }

    struct dirent *entry;
	time_t file_time;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, hash_str, strlen(hash_str)) == 0) {
            printf("Found file: %s\n", entry->d_name);

			// Get timestamp from the last 32 characters + null terminator
			char hex_timestamp[33];
			if (strlen(entry->d_name) == 64) {
				strncpy(hex_timestamp, entry->d_name + strlen(entry->d_name) - 32, 32);
				hex_timestamp[32] = '\0';

				printf("Hex timestamp: %s\n", hex_timestamp);

				// Convert the hexadecimal string to a time_t value
				file_time = (time_t)strtoul(hex_timestamp, NULL, 16);
				printf("Extracted time_t: %ld\n", file_time);
				printf("Current time: %ld\n", time(NULL) - file_time);
				if (time(NULL) - file_time < timeout_value) {
					printf("File is still valid in cache\n");
					closedir(dir);
            		return 1;  // File found
				} else {
					// printf("File is expired, removing from cache\n");
					// remove file from cache
					char filepath[strlen(CACHE) + 32 + 1 + 32];
					bzero(filepath, sizeof(filepath));
					strcpy(filepath, CACHE);
					strcat(filepath, entry->d_name);
					if (remove(filepath) == 0) {
						printf("File removed from cache\n");
					} else {
						perror("Error removing file");
					}
				}
			} else {
				printf("File name length is not 64 characters\n");
				closedir(dir);
				return 0;  // File not found
			}
		}
    }

    closedir(dir);
    return 0;  // File not found
}

int add_file_to_cache(int clientfd, char* req, ParsedURL* url, char* file_hash) {
	printf("add_file_to_cache\n");
	struct sockaddr_in server_addr;
    int serverfd;
	struct hostent *he;
	
	// Get hostname
    if ((he = gethostbyname(url->host)) == NULL) {
        // Send 404 not found if hostname can't be resolved
        strcpy("HTTP/1.1 404 Not Found\r\n\r\n<html><body><h1>404 Not Found</h1><p>Could not resolve hostname.</p></body></html>", req);
        write(clientfd, req, strlen(req));
        return 0;
    }

    // Create socket to server
    if ((serverfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Server socket creation failed");
        return 0;
    }
    
    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(url->port);
    memcpy(&server_addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    // Connect to server
    if (connect(serverfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection to server failed");
        close(serverfd);
        return 0;
    }
    
    // Send request to server
    if (write(serverfd, req, strlen(req)) < 0) {
        printf("Request send failed");
        close(serverfd);
        return 0;
    }
    
    // Create file
    char filepath[strlen(CACHE) + 32 + 32 + 1];
	bzero(filepath, sizeof(filepath));
	strcpy(filepath, CACHE);
	strcat(filepath, file_hash);
	
	// Get the current time and convert to hex string
    time_t current_time = time(NULL);
    if (current_time == ((time_t)-1)) {
        perror("Failed to get the current time");
        return 1;
    }

    char hex_timestamp[33];
    snprintf(hex_timestamp, sizeof(hex_timestamp), "%032lx", (unsigned long)current_time);
    printf("Current time: %s\n", hex_timestamp);
	hex_timestamp[32] = '\0';
	
	// Append the timestamp to the file name
	strcat(filepath, hex_timestamp);

	printf("filepath = %s\n", filepath);
    
    FILE *file = fopen(filepath, "wb");
    if (file == NULL) {
        printf("Failed to create response file");
        close(serverfd);
        return 0;
    }
    
    // Read response from server and save to file
    char buffer[BUF_SIZE];
    ssize_t bytes_read;
    
    while ((bytes_read = read(serverfd, buffer, BUF_SIZE)) > 0) {
        fwrite(buffer, 1, bytes_read, file);
    }
    
    // Close the file and server socket
    fclose(file);
    close(serverfd);
    return 1;
}

// Send file content
int send_file(int clientfd, char* filename) {
	printf("send_file\n");

    FILE *file = NULL;
    char buffer[BUF_SIZE];
    size_t bytesRead;
	struct dirent *entry;

	DIR *dir = opendir(CACHE);
    if (dir == NULL) {
        perror("Failed to open directory");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        // Check for files containing the hash
        if (strstr(entry->d_name, filename) != NULL) {
            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s%s", CACHE, entry->d_name);

            // Open the file
            file = fopen(filepath, "rb");
            if (file == NULL) {
                perror("Error opening file");
                closedir(dir);
                return -1;
            }

            printf("Opened file: %s\n", filepath);
			break;
        }
    }
    
	// Send file content
    while ((bytesRead = fread(buffer, 1, BUF_SIZE, file)) > 0) {
        if (send(clientfd, buffer, bytesRead, 0) == -1) {
            perror("Error sending file data");
            fclose(file);
            return -1;
        }
    }

    // Check for errors in reading file
    if (ferror(file)) {
        perror("Error reading file");
        fclose(file);
        return -1;
    }

    fclose(file);
    return EXIT_SUCCESS;
}


/******************************** CTRL-C Handler ********************************/

/**
 * for INThandler
 */
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
	printf("\nProxy exiting...\n");
	pthread_t timer_thread;

	if (serverfd != -1) {
		pthread_create(&timer_thread, NULL, watchdog_timer, NULL); // start timer
		while (wait(NULL)>0) {} 	// wait for child processes to terminate
        close(serverfd);
        printf("Proxy socket closed.\n");
		pthread_cancel(timer_thread);	// end timer
    }
	 exit(0);
}