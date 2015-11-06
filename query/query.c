#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "sha1.h"

#define MAX_LINE 2048

unsigned hash(char* portstr){
    SHA1_CTX sha;
    uint8_t results[20];
    char * buf;
    int n;
    uint8_t chunks0[4];
    uint8_t chunks1[4];
    uint8_t chunks2[4];
    uint8_t chunks3[4];
    uint8_t chunks4[4];
    uint8_t ans[4];
    
    buf = portstr;
    n = strlen(buf);
    SHA1Init(&sha);
    SHA1Update(&sha, (uint8_t*)buf, n);
    SHA1Final(results, &sha);
    
    strncpy(chunks0, results, 4);
    strncpy(chunks1, results + 4, 4);
    strncpy(chunks2, results + 4*2, 4);
    strncpy(chunks3, results + 4*3, 4);
    strncpy(chunks4, results + 4*4, 4);
    
    for(int i = 0; i < 5; i++){
        ans[i] = chunks0[i] ^ chunks1[i] ^ chunks2[i] ^ chunks3[i] ^ chunks4[i];
    }
    return *(unsigned*)ans;
}


int main(int argc, char* argv[]){
	char* cmd, *response, *saveptr;
	cmd = (char*)malloc(50 * sizeof(char));
	response = (char*)malloc(50 * sizeof(char));

	printf("Enter command(query) ip(first) port(second) :\n");
	fgets(cmd, 50, stdin);
	memset(response, 0, 50);
	
    response = strtok_r(cmd, " ", &saveptr);
	while(strcmp(response, "query")){
		memset(cmd, 0, 50);
		printf("Incorrect request, please enter command(query) ip(first) port(second) again:\n");
		fgets(cmd, 50, stdin);
		response = strtok_r(cmd, " ", &saveptr);
	}
    response = strtok_r(NULL, " ", &saveptr);
    response = strtok_r(NULL, " ", &saveptr);
	int port=atoi(response);
	char* ipaddr = "127.0.0.1";
	int sock;
	struct sockaddr_in server_addr;

	char buf_receive[MAX_LINE], buf_response[MAX_LINE];
	memset(buf_receive,0,MAX_LINE);
	memset(buf_response,0,MAX_LINE);
	if ((sock = socket(AF_INET, SOCK_STREAM/* use tcp */, 0)) < 0) {
		perror("Create socket error: ");
		return 1;
	}
	server_addr.sin_addr.s_addr = inet_addr(ipaddr);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
		perror("Connect error: ");
	    return 1;
	}

	char* str;
	char* portstr;
	
    str = (char*)malloc(30 * sizeof(char));
	portstr = (char*)malloc(20 * sizeof(char));
    
	strcat(str,ipaddr);
	strcat(str," ");
	sprintf(portstr, "%d", port);
	strcat(str, portstr);
    
	printf("Connection to node 127.0.0.1, port %d, position %u\n", port, hash(str));
	
    memcpy(buf_receive,"query",sizeof("query"));
	
    if (send(sock, buf_receive, sizeof(buf_receive), 0) < 0) {
		perror("Send error: ");
		return 1;
	}

	//receive fingertable from port node
	while(1){
		fflush(stdin);
		memset(buf_receive, 0, MAX_LINE);
		memset(buf_response, 0, MAX_LINE);
		printf("Please enter your search key (or type 'quit' to leave):\n");
		fgets(buf_receive,MAX_LINE,stdin);
        
		if(!strcmp(buf_receive,"quit\n")) break;
		buf_receive[sizeof(buf_receive)-1] = '\0';
		printf("%sHash value is 0x%X\n",buf_receive,hash(buf_receive));
        
		if((send(sock, buf_receive, sizeof(buf_receive),0)) < 0){
			perror("Send error: ");
			return 1;
		}
		if((recv(sock, buf_response, MAX_LINE ,0)) < 0) {
			perror("Recv error: ");
			return 1;
		}
		memset(str,0,30);
		strcat(str,ipaddr);
		strcat(str," ");
		strcat(str,buf_response);
		printf("Response from node 127.0.0.1, port %d, position 0x%x:\nNot found.\n", atoi(buf_response),hash(str));
	}
	printf("query quited\n");
	return 0;
}
