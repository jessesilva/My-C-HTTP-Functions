
/*
** Language: Portuguese Brazilian.
** Autor: Constantine - 07/2015.
** My GitHub: github.com/jessesilva
** Team GitHub: github.com/p0cl4bs
** Descrição: Conjunto de funções utilizadas para comunicações via socket.
** Compilar...
**  Windows: gcc --std=c99 socket.c -lws2_32 -o socket.exe && socket.exe
**  Linux: gcc -g -Wall -std=c99 socket.c -o socket ; ./socket
*/

#define WINUSER /* Comente esta linha se você for usuário Linux. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef WINUSER
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#define close closesocket
#define sleep Sleep
#else
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#define say printf
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0 
#endif

typedef struct {
	unsigned int status;
	unsigned int length;
	unsigned char *content;
} http_request_t;

typedef struct {
	unsigned int port;
	unsigned int length;
	unsigned char *content;
	unsigned char *domain;
	unsigned char *path;
} url_t;

static unsigned int http_request_init(void) {
#ifdef WINUSER
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2,2), &wsadata) != 0) {
		say("WSAStartup failed!\n");
		exit(EXIT_FAILURE);
	}
#endif
	return FALSE;
}

static unsigned int http_request_cleanup(void) {
#ifdef WINUSER
	WSACleanup();
#endif
	return FALSE;
}

static url_t *http_request_parse_url(const unsigned char *url) {
	if (!url) return (url_t *) NULL;
	
	url_t *new_url = (url_t *) malloc(sizeof(url_t));
	if (!new_url) {
		say("http_request_parse_url() - Error to alloc memory, url_t struct.\n");
		return (url_t *) NULL;
	}
	
	new_url->port = 80;
	new_url->length = 0;
	new_url->content = NULL;
	new_url->domain = NULL;
	new_url->path = NULL;
	
	if (!(new_url->content = (unsigned char *) malloc(strlen(url) + 1))) {
		free(new_url);
		say("http_request_parse_url() - Error to alloc memory, content struct field.\n");
		return (url_t *) NULL;
	}
	
	memset(new_url->content, '\0', strlen(url) + 1);
	memcpy(new_url->content, url, strlen(url));
	new_url->length = strlen(new_url->content);
	
	if (!new_url->length > 0 || !strlen(new_url->content) > 0) {
		if (new_url->content != NULL) 
			free(new_url->content);
		free(new_url);
		say("http_request_parse_url() - No specified URL.\n");
		return (url_t *) NULL;
	}
	
	unsigned int start_pointer = 0;
	unsigned char *u_ptr = new_url->content;
	if (strstr(u_ptr, "://")) {
		if (!(u_ptr[0] == 'h' && u_ptr[1] == 't' && u_ptr[2] == 't' && u_ptr[3] == 'p' && 
			  u_ptr[4] == ':' && u_ptr[5] == '/' && u_ptr[6] == '/')) {
			free(new_url->content);
			free(new_url);
			say("http_request_parse_url() - Only supported HTTP.\n");
			return (url_t *) NULL;
		} else 
			start_pointer = strlen("http://");
	}
	
	u_ptr += start_pointer;
	unsigned int counter = 0;
	unsigned char *c_port = NULL;
	unsigned char *p_ptr = NULL;
	if ((p_ptr = strstr(u_ptr, ":")) != NULL && ++p_ptr) {
		if ((c_port = (unsigned char *) malloc(sizeof(unsigned char) * 10)) != NULL) {
			for (int a=0; p_ptr[a]!='\0'; a++) {
				counter = 0;
				for (int b='0'; b<='9' ; b++)
					if (p_ptr[a] == b)
						counter++;
				if (!counter > 0) {
					c_port[a] = '\0';
					break;
				}
				c_port[a] = p_ptr[a];
			}
			if (c_port != NULL)
				new_url->port = (int) strtol(c_port, NULL, 10);
			free(c_port);
		}
	}
	
	if (new_url->port == 0)
		new_url->port = 80;
	
	if (!new_url->port > 0) {
		if (c_port)
			free(c_port);
		if (new_url->content != NULL) 
			free(new_url->content);
		free(new_url);
		say("http_request_parse_url() - Port parsing error.");
		return (url_t *) NULL;
	}
	
	unsigned char *c_domain = NULL;
	if ((c_domain = (unsigned char *) malloc(sizeof(unsigned char) * (256*2))) != NULL) {
		memset(c_domain, '\0', sizeof(unsigned char) * (256*2));
		for (int d=0; d<256; d++) {
			counter = 0;
			for (int a='a',b='A',c='0'; a<='z'; a++,b++) {
				if (u_ptr[d] == a || u_ptr[d] == b || u_ptr[d] == c || 
					u_ptr[d] == '.' || u_ptr[d] == '-')
					counter++;
				if (c <= '9')
					b++;
			}
			if (counter == 0) {
				c_domain[d] = '\0';
				if ((new_url->domain = (unsigned char *) malloc(sizeof(unsigned char) * (d + 1))) != NULL) {
					memset(new_url->domain, '\0', sizeof(unsigned char) * (d + 1));
					memcpy(new_url->domain, c_domain, d);
				}
				break;
			}
			c_domain[d] = u_ptr[d];
		}
		free(c_domain);
	}
	
	if (new_url->domain == NULL) {
		if (c_domain)
			free(c_domain);
		if (c_port)
			free(c_port);
		if (new_url->content != NULL) 
			free(new_url->content);
		free(new_url);
		say("http_request_parse_url() - Domain parsing error.");
		return (url_t *) NULL;
	}
	
	unsigned char *c_path = NULL;
	if ((c_path = (unsigned char *) malloc( sizeof(unsigned char) * (new_url->length + (256*2)) )) != NULL) {
		memset(c_path, '\0', sizeof(unsigned char) * (new_url->length + (256*2)));
		counter = 0;
		for (int a=0; u_ptr[a]!='\0'; a++) {
			if (u_ptr[a] == '/') {
				counter++;
				break;
			}
		}
		if (counter > 0) {
			unsigned char *p_ptr = strstr(u_ptr, "/");
			if (p_ptr != NULL) {
				unsigned int a = 0;
				for (; p_ptr[a]!='\0'; a++)
					c_path[a] = p_ptr[a];
				if ((new_url->path = (unsigned char *) malloc(sizeof(unsigned char) * (a + 1))) != NULL) {
					memset(new_url->path, '\0', sizeof(unsigned char) * (a + 1));
					memcpy(new_url->path, c_path, a);
				}
			}
		} else {
			unsigned char bar [] = "/";
			if ((new_url->path = (unsigned char *) malloc(sizeof(unsigned char) * (strlen(bar) + 1))) != NULL) {
				memset(new_url->path, '\0', sizeof(unsigned char) * (strlen(bar) + 1));
				memcpy(new_url->path, bar, strlen(bar));
			}
		}
		free(c_path);
	}
	
	if (new_url->path == NULL) {
		if (c_path)
			free(c_path);
		if (c_domain)
			free(c_domain);
		if (c_port)
			free(c_port);
		if (new_url->content != NULL) 
			free(new_url->content);
		free(new_url);
		say("http_request_parse_url() - Path parsing error.");
		return (url_t *) NULL;
	}
	
	if (new_url != NULL)
		return new_url;
	
	return (url_t *) NULL;
}

#define FREE_URL_FORMATED \
	url_formated->port = 0;\
	url_formated->length = 0;\
	if (url_formated->content != NULL)\
		url_formated->content = NULL;\
	if (url_formated->domain != NULL)\
		url_formated->domain = NULL;\
	if (url_formated->path != NULL)\
		url_formated->path = NULL
static http_request_t *http_get_request(const unsigned char *url) {
	if (!url) return (http_request_t *) NULL;
	
	url_t *url_formated = http_request_parse_url(url);
	if (url_formated == NULL) {
		say("http_get_request() - Error to alloc url_t struct.\n");
		return (http_request_t *) NULL;
	}
	
	struct hostent *host_information = gethostbyname(url_formated->domain);
	if (host_information == NULL) {
		FREE_URL_FORMATED;
		say("http_get_request() - gethostbyname failed.\n");
		return (http_request_t *) NULL;
	}
	
	struct sockaddr_in address;
	address.sin_family      = AF_INET;
	address.sin_port        = htons(url_formated->port);
	address.sin_addr.s_addr = *(u_long *) host_information->h_addr_list[0];
	
	int sock = (int)(-1);
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		FREE_URL_FORMATED;
		say("http_get_request() - socket failed.\n");
		return (http_request_t *) NULL;
	}
	
	int result = (int)(-1);
	if ((result = connect(sock, (struct sockaddr *)&address, sizeof(address))) < 0) {
		FREE_URL_FORMATED;
		close(sock);
		say("http_get_request() - connect failed.\n");
		return (http_request_t *) NULL;
	}
	
	unsigned char *header = NULL;
	if (!(header = (unsigned char *) malloc(sizeof(unsigned char) * ((256*5) + strlen(url) + 1)))) {
		FREE_URL_FORMATED;
		close(sock);
		say("http_get_request() - Error alloc memory to header.\n");
		return (http_request_t *) NULL;
	}
	memset(header, '\0', sizeof(unsigned char) * ((256*5) + strlen(url) + 1));
	sprintf(header, 
		"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Connection: close\r\n\r\n", url_formated->path, url_formated->domain);
	
	if (send(sock, header, strlen(header), 0) == -1) {
		FREE_URL_FORMATED;
		free(header);
		close(sock);
		say("http_get_request() - send failed.\n");
		return (http_request_t *) NULL;
	}
	
	result = 0;
	unsigned int is_going = 1;
	unsigned int total_length = 0;
	unsigned char *response = (unsigned char *) malloc(sizeof(unsigned char) * (256*2));
	unsigned char *response_final = (unsigned char *) malloc(sizeof(unsigned char) * (256*2));
	
	if (!response || !response_final) {
		FREE_URL_FORMATED;
		free(header);
		if (response)
			free(response);
		if (response_final)
			free(response_final);
		close(sock);
		say("http_get_request() - Error alloc memory to receive data.\n");
		return (http_request_t *) NULL;
	}
	
	memset(response, '\0', sizeof(unsigned char) * (256*2));
	memset(response_final, '\0', sizeof(unsigned char) * (256*2));
	
	while (is_going) {
		result = recv(sock, response, (sizeof(unsigned char) * (256*2)) - 1, 0);
		if (result == 0 || result < 0)
			is_going = 0;
		else {
			if ((response_final = (unsigned char *) realloc(response_final, total_length + 
				(sizeof(unsigned char) * (256*2)))) != NULL) {
				memcpy(&response_final[total_length], response, result);
				total_length += result;
			}
		}
	}
	
	unsigned int result_flag = FALSE;
	http_request_t *request = (http_request_t *) malloc(sizeof(http_request_t));
	if (request != NULL) {
		memset(request, 0, sizeof(http_request_t));
		request->status = FALSE;
		request->length = 0;
		request->content = NULL;
		
		if (total_length > 0) {
			request->length = total_length;
			if ((request->content = (unsigned char *) malloc(sizeof(unsigned char) * (request->length+1))) != NULL) {
				memset(request->content, '\0', sizeof(unsigned char) * (request->length+1));
				memcpy(request->content, response_final, request->length);
				request->status = TRUE;
				result_flag = TRUE;
			}
		}
	}
	
	close(sock);
	free(header);
	free(response);
	free(response_final);
	
	url_formated->port = 0;
	url_formated->length = 0;
	if (url_formated->content)
		free(url_formated->content);
	if (url_formated->domain)
		free(url_formated->domain);
	if (url_formated->path)
		free(url_formated->path);
	free(url_formated);
	
	if (result_flag == TRUE)
		return request;
	else {
		if (request != NULL)
			free(request);
	}
	
	return (http_request_t *) NULL;
}

static http_request_t *http_send_raw(const unsigned char *host, const unsigned int port, const unsigned char *header) {
	if (!host || !header) return (http_request_t *) NULL;
	
	struct hostent *host_information = gethostbyname(host);
	if (host_information == NULL) {
		say("http_send_raw() - gethostbyname failed.\n");
		return (http_request_t *) NULL;
	}
	
	struct sockaddr_in address;
	address.sin_family      = AF_INET;
	address.sin_port        = htons(port);
	address.sin_addr.s_addr = *(u_long *) host_information->h_addr_list[0];
	
	int sock = (int)(-1);
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		say("http_send_raw() - socket failed.\n");
		return (http_request_t *) NULL;
	}
	
	int result = (int)(-1);
	if ((result = connect(sock, (struct sockaddr *)&address, sizeof(address))) < 0) {
		close(sock);
		say("http_send_raw() - connect failed.\n");
		return (http_request_t *) NULL;
	}
	
	if (send(sock, header, strlen(header), 0) == -1) {
		close(sock);
		say("http_send_raw() - send failed.\n");
		return (http_request_t *) NULL;
	}
	
	result = 0;
	unsigned int is_going = 1;
	unsigned int total_length = 0;
	unsigned char *response = (unsigned char *) malloc(sizeof(unsigned char) * (256*2));
	unsigned char *response_final = (unsigned char *) malloc(sizeof(unsigned char) * (256*2));
	
	if (!response || !response_final) {
		if (response)
			free(response);
		if (response_final)
			free(response_final);
		close(sock);
		say("http_send_raw() - Error alloc memory to receive data.\n");
		return (http_request_t *) NULL;
	}
	
	memset(response, '\0', sizeof(unsigned char) * (256*2));
	memset(response_final, '\0', sizeof(unsigned char) * (256*2));
	
	while (is_going) {
		result = recv(sock, response, (sizeof(unsigned char) * (256*2)) - 1, 0);
		if (result == 0 || result < 0)
			is_going = 0;
		else {
			if ((response_final = (unsigned char *) realloc(response_final, total_length + 
				(sizeof(unsigned char) * (256*2)))) != NULL) {
				memcpy(&response_final[total_length], response, result);
				total_length += result;
			}
		}
	}
	
	unsigned int result_flag = FALSE;
	http_request_t *request = (http_request_t *) malloc(sizeof(http_request_t));
	if (request != NULL) {
		memset(request, 0, sizeof(http_request_t));
		request->status = FALSE;
		request->length = 0;
		request->content = NULL;
		
		if (total_length > 0) {
			request->length = total_length;
			if ((request->content = (unsigned char *) malloc(sizeof(unsigned char) * (request->length+1))) != NULL) {
				memset(request->content, '\0', sizeof(unsigned char) * (request->length+1));
				memcpy(request->content, response_final, request->length);
				request->status = TRUE;
				result_flag = TRUE;
			}
		}
	}
	
	close(sock);
	free(response);
	free(response_final);
	
	if (result_flag == TRUE)
		return request;
	else {
		if (request != NULL)
			free(request);
	}
	
	return (http_request_t *) NULL;
}

static http_request_t *http_request_free(http_request_t *request) {
	if (!request) return (http_request_t *) NULL;
	
	request->length = 0;
	request->status = FALSE;
	free(request->content);
	free(request);
	
	return (http_request_t *) NULL;
}

int main(int argc, char **argv) {
	
	/* Initialize. */
	http_request_init();
	
	/* Send HTTP GET. */
	http_request_t *request = http_get_request("http://google.com/test.php?id=123");
	if (request != NULL) {
		if (request->status == TRUE)
			say("Content...%s\nLength: %d\n", request->content, request->length);
		http_request_free(request);
	}
	
	/* Send raw data to host. */
	http_request_t *request_ex = http_send_raw(
		"google.com", 80,
		
		"GET /test.php?id=123 HTTP/1.1\r\n"
		"Host: google.com\r\n"
		"Connection: close\r\n\r\n");
		
	if (request_ex != NULL) {
		if (request_ex->status == TRUE)
			say("Content...%s\nLength: %d\n", request_ex->content, request_ex->length);
		http_request_free(request_ex);
	}
	
	/* Tests... */
	http_request_t *request_test = NULL;
	for (int a=0; a<100; a++) {
		if ((request_test = http_send_raw(
				"google.com", 80,
				"GET /test.php?id=123 HTTP/1.1\r\n"
				"Host: google.com\r\n"
				"Connection: close\r\n\r\n")) != NULL) {
					
			if (request_test->status == TRUE)
				say("Request: %d\nData length: %d\n\n", a, request_test->length);
			
			http_request_free(request_test);
		} else {
			say("Error alloc memory - Tests.\n");
			exit(EXIT_FAILURE);
		}
		Sleep(10);
	}
	
	/* Cleanup. */
	http_request_cleanup();
	
	return 0;
}
