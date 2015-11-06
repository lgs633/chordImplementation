#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>

#include "sha1.h"

#define MAX_LINE 2048
#define KEY_BITS 32

//===========Define Struct=================

typedef struct _Node{
    int port;
    //char* IP;
    unsigned key;
}Node;

typedef struct _FingerTable{
    unsigned start;
    Node* ftnode;
}FingerTable;

//================Define variables============
FingerTable fingertable[KEY_BITS];
Node* successor;
Node* successor2;
Node* predecessor;
Node node;
char* ip="127.0.0.1";

//=============Interface of functions========

unsigned hash_func(char* key);
unsigned hash_str(int port);

void* join_node(void* sock);
int closest_port_find(unsigned key);
void* finger_table_update();
void predecessor_update();

void fix_fingers(int i);
void notify();
void stabilize();
void heart_beat();
void listen_func(int clientfd);

void* read_input();
void* print_func();


//==============Implementation of functions========
//1. print
void* print_func(){
    while(1){
        if(predecessor == NULL) continue;
        printf("You are listening on port %d.\n", node.port);
        printf("Your position is 0x%x.\n", node.key);
        printf("Your predecessor is node %s, port %d, position 0x%x.\n", ip, predecessor->port, predecessor->key);
        printf("Your successor is node %s, port %d, position 0x%x.\n", ip, successor->port, successor->key);
        printf("To close the node, enter 'kill' or CTL x + CTL c.\n");
        sleep(5);
    }
}
//2. hash function then get key
unsigned hash_func(char* portstr){
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

unsigned hash_str(int port){
	char* str;
	char* portstr;
	str = (char*)malloc(KEY_BITS*sizeof(char));
	portstr = (char*)malloc(KEY_BITS*sizeof(char));
	strcat(str, "127.0.0.1 ");
	sprintf(portstr, "%d", port);
	strcat(str, portstr);
	return hash_func(str);
}


//3. find
int closest_port_find(unsigned key){
	if((key > node.key) && (key <= successor->key)){
		return successor->port;
	}
	else if(((key > node.key) || (key < successor->key))
			&& (node.key > successor->key)){
		return successor->port;
	}
	else{
        int i;
	    for(i=31;i>=0;i--){
			if(((key < node.key) && (fingertable[i].ftnode->key > node.key))||((node.key < fingertable[i].ftnode->key) &&(fingertable[i].ftnode->key < key))||
					((key < node.key) && (fingertable[i].ftnode->key < key))){
				int sock;
				struct sockaddr_in server_addr;
				char buf_buf_msg[MAX_LINE], buf_reply[MAX_LINE];
				
                if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
					perror("Create socket error:");
				    return 0;
				}
				server_addr.sin_addr.s_addr = inet_addr(ip);
				server_addr.sin_family = AF_INET;
				server_addr.sin_port = htons(fingertable[i].ftnode->port);

				if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
					perror("Connect error: ");
					return 0;
				}

				memset(buf_buf_msg,0,sizeof(buf_buf_msg));
				sprintf(buf_buf_msg,"find %u",key);

				if(send(sock, buf_buf_msg, MAX_LINE, 0) < 0){
				    perror("Send error:");
				    return 0;
				}
                
				memset(buf_reply,0,sizeof(buf_reply));
				if(recv(sock, buf_reply, MAX_LINE, 0) < 0){
					perror("Recv error: ");
					return 0;
				}

				int recvPort;
				recvPort=atoi(buf_reply);
				close(sock);
				return recvPort;
			}
	    }
    }
	return node.port;
}

//4. join and update
void fix_fingers(int i){
	int return_port;
	return_port = closest_port_find(fingertable[i].start);
	while(return_port == 0){
		return_port=closest_port_find(fingertable[i].start);
	}
	fingertable[i].ftnode->port = return_port;
	fingertable[i].ftnode->key = hash_str(fingertable[i].ftnode->port);
}


void notify(){
	int fd;
	struct sockaddr_in server_addr;
	char buf_buf_msg[MAX_LINE];

	if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		perror("Create socket error:");
	    return;
	}
	server_addr.sin_addr.s_addr = inet_addr(ip);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(successor->port);

	if(connect(fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
		successor->port = successor2->port;
		successor->key = hash_str(successor->port);
		successor2->port = node.port;
		successor2->key = hash_str(successor2->port);
		server_addr.sin_port = htons(successor->port);
		predecessor_update(successor->port);
		if(connect(fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
			perror("Connect error:");
			return;
		}
	}

    
	memset(buf_buf_msg,0,sizeof(buf_buf_msg));
	sprintf(buf_buf_msg,"notify %d",node.port);
	if(send(fd, buf_buf_msg, MAX_LINE, 0) < 0){
	    perror("Send error:");
	    return;
	}
	close(fd);
}

void stabilize(){
	int sock;
	struct sockaddr_in server_addr;
	char buf_buf_msg[MAX_LINE], buf_reply[MAX_LINE];

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		perror("Create socket error:");
	    return;
	}
	server_addr.sin_addr.s_addr = inet_addr(ip);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(successor->port);

	if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
		successor->port = successor2->port;
		successor->key = hash_str(successor->port);
		successor2->port = node.port;
		successor2->key = hash_str(successor2->port);
		server_addr.sin_port = htons(successor->port);
		predecessor_update(successor->port);
		if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
			perror("Connect error:");
			return;
		}
	}

	memset(buf_buf_msg,0,sizeof(buf_buf_msg));
	sprintf(buf_buf_msg,"stabilize %d",node.port);

	if(send(sock, buf_buf_msg, MAX_LINE, 0) < 0){
	    perror("Send error:");
	    return;
	}

	memset(buf_reply,0,sizeof(buf_reply));
	if(recv(sock, buf_reply, MAX_LINE, 0) < 0){
		perror("Recv error: ");
		return;
	}

	int recvPort;
	unsigned recvHash;
	recvPort=atoi(buf_reply);
	recvHash=hash_str(recvPort);
	if(recvPort>0){
	    if((successor->key > node.key) && (node.key < recvHash) && (recvHash < successor->key)){
	    	successor->port = recvPort;
	    	successor->key = hash_str(successor->port);
	    }
	    else if((successor->key < node.key) && (recvPort!=node.port) &&
	    		((recvHash > node.key) || (recvHash < successor->key))){
	    	successor->port = atoi(buf_reply);
	    	successor->key = hash_str(successor->port);
	    }
	}
	close(sock);
}

void predecessor_update(int port){
	int sock;
	struct sockaddr_in server_addr;
	char buf_msg[MAX_LINE];

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		perror("Create socket error:");
	    return;
	}
    
    server_addr.sin_addr.s_addr = inet_addr(ip);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
		perror("Connect error in reset:");
		return;
	}

	memset(buf_msg,0,sizeof(buf_msg));
	sprintf(buf_msg,"predecessor_update");

	if(send(sock, buf_msg, MAX_LINE, 0) < 0){
	    perror("Send error:");
	    return;
	}
	close(sock);
}

void heart_beat(){
	if(predecessor!=NULL){
		int sock;
		struct sockaddr_in server_addr;
		char buf_msg[MAX_LINE];

		if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
			perror("Create socket error:");
		    return;
		}
		server_addr.sin_addr.s_addr = inet_addr(ip);
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(predecessor->port);
		if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
			free(predecessor);
			predecessor = NULL;
			perror("Connect error in heart_beat: ");
			return;
		}

		memset(buf_msg,0,sizeof(buf_msg));
		sprintf(buf_msg,"keep_alive %d",successor->port);

		if(send(sock, buf_msg, MAX_LINE, 0) < 0){
		    perror("Send error:");
		    return;
		}
		close(sock);
	}
}

void* finger_table_update(){
    int i;
	while(1){
		for(i=0;i < KEY_BITS;i++){
			fix_fingers(i);
		}
		sleep(1);
		stabilize();
		notify();
		heart_beat();
	}
	pthread_exit(0);
}


void* join_node(void* sock){
	char buf_msg[MAX_LINE];
	char buf_reply[MAX_LINE];
	int result;
	char* cmd = (char*)malloc(30*sizeof(char));
	char* token = " ";
	int connfd = *(int*)sock;
	free(sock);
	while((recv(connfd,buf_msg,sizeof(buf_msg),0))>0){
    	cmd = strtok(buf_msg,token);
    	if(!strcmp(cmd,"join")){
    		cmd = strtok(NULL,token);
    		Node* n;
    		n = (Node*)malloc(sizeof(Node));
    		n->port = atoi(cmd);
    		n->key = hash_str(n->port);
    		if(successor->port == node.port){
    			successor->port = n->port;
        		successor->key = hash_str(successor->port);
   	    		predecessor->port = n->port;
   	    		predecessor->key = hash_str(predecessor->port);
   	    		result = node.port;
    		}
    		else {
    			result = closest_port_find(n->key);
    			while(result == 0){
    				result = closest_port_find(n->key);
    			}
    		}
	    	memset(buf_reply,0,MAX_LINE);
	    	sprintf(buf_reply, "%d", result);
	    	if(send(connfd, buf_reply, MAX_LINE, 0) < 0){
	    		perror("Send error: ");
	    		return NULL;
	    	}
    	}
    	else if(!strcmp(cmd,"find")){
    		cmd = strtok(NULL,token);
    		unsigned findHash;
    		findHash = atoi(cmd);
    		result = closest_port_find(findHash);
    		while(result == 0){
    			result=closest_port_find(findHash);
    		}
    		sprintf(buf_reply,"%d",result);
    		if(send(connfd, buf_reply, MAX_LINE, 0) < 0){
    			perror("Send error: ");
        		return NULL;
    	   	}
    	}
    	else if(!strcmp(cmd,"query")){
    		while((recv(connfd, buf_msg, MAX_LINE,0))>0){
    			unsigned mHash;
    			mHash = hash_func(buf_msg);
    			result = closest_port_find(mHash);
    			while(result == 0){
    				result = closest_port_find(mHash);
    			}
    			sprintf(buf_reply,"%d",result);
    			if(send(connfd, buf_reply, MAX_LINE, 0) < 0){
    				perror("Send error: ");
    				return NULL;
    			}
    		}
    	}
    	else if(!strcmp(cmd,"stabilize")){
    		memset(buf_reply,0,MAX_LINE);
    		if(predecessor == NULL){
    			sprintf(buf_reply,"0");
    		}
    		else{
    			sprintf(buf_reply,"%d",predecessor->port);
    		}
    		if(send(connfd, buf_reply, MAX_LINE, 0) < 0){
    			perror("Send error: ");
    			return NULL;
    	    }
    		break;
    	}
    	else if(!strcmp(cmd,"notify")){
    		cmd = strtok(NULL,token);
    		result = atoi(cmd);
    		if(predecessor == NULL){
    			predecessor = (Node*)malloc(sizeof(Node));
    			predecessor->port = result;
    			predecessor->key = hash_str(predecessor->port);
    		}
    		else if((predecessor->key < node.key) && (predecessor->key < hash_str(result)) && (hash_str(result) < node.key)){
    			predecessor->port = result;
    			predecessor->key = hash_str(predecessor->port);
    		}
    		else if((predecessor->key > node.key) &&
    				((hash_str(result) > predecessor->key) || (hash_str(result) < node.key))){
    			predecessor->port = result;
    			predecessor->key = hash_str(predecessor->port);
    		}
    	}
    	else if(!strcmp(cmd,"keep_alive")){
    		cmd=strtok(NULL,token);
    		result=atoi(cmd);
    		successor2->port = result;
    		successor2->key = hash_str(successor2->port);
    	}
    	else if(!strcmp(cmd,"predecessor_update")){
    		free(predecessor);
    		predecessor = NULL;
    	}
    	memset(buf_msg,0,sizeof(buf_msg));
	}
	close(connfd);
	pthread_exit(0);
}

//5. listen for command, then execute the next step

void listen_func(int clientfd){
    char buf_msg[MAX_LINE], buf_reply[MAX_LINE];
    memset(buf_msg,0,sizeof(buf_msg));
    memset(buf_reply,0,sizeof(buf_msg));
    
    printf("Joining the Chord ring.\n");
    sprintf(buf_msg,"join %d",node.port);
    int sock;
    struct sockaddr_in server_addr;
    
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("Create socket error: ");
        return;
    }
    
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(clientfd);
    
    if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        perror("Connect error in join: ");
        return;
    }
    
    if(send(sock, buf_msg, sizeof(buf_msg),0) < 0){
        perror("Send error: ");
        return;
    }
    
    fflush(stdin);
    if((read(sock, buf_reply, MAX_LINE)) < 0){
        perror("Recv error: ");
        return;
    }
    successor->port=atoi(buf_reply);
    successor->key=hash_str(successor->port);
    close(sock);
}

//6. read command from command line that user entered
void* read_input(){
    char* cmd = malloc(MAX_LINE*sizeof(char));
    memset(cmd,0,MAX_LINE);
    while(strcmp(cmd,"kill") != 0){
        fscanf(stdin,"%s",cmd);
    }
    exit(0);
}

// 7. main function

int main(int argc, char** argv){
    char* cmd, *parse;
	int clientfd;
    char* token = " ";
    void* self;
    node.key=0;
	node.port=0;
	successor=(Node*)malloc(sizeof(Node));
	successor2=(Node*)malloc(sizeof(Node));
	predecessor = NULL;
   
	cmd=(char*)malloc(50*sizeof(char));
	parse=(char*)malloc(50*sizeof(char));

	printf("Please input command from keyboard:\n");
	fgets(cmd, 1024, stdin);
	parse = strtok(cmd, token);
	parse = strtok(NULL, token);
	node.port = atoi(parse);
	node.key = hash_str(node.port);
	parse = strtok(NULL, token);

    int i;
	for( i = 0; i < KEY_BITS; i++){
		fingertable[i].start = node.key + pow(2,i);
		fingertable[i].ftnode = (Node*)malloc(sizeof(Node));
		fingertable[i].ftnode->port = node.port;
		fingertable[i].ftnode->key = hash_str(fingertable[i].ftnode->port);
	}
	successor2->port=node.port;
	successor2->key=hash_str(successor2->port);
//if it is the first node, then parse should be NULL
	if(parse == NULL){
		//create_node;
        //initialize successor and predecessor as the value of local node
        predecessor=(Node*)malloc(sizeof(Node));
        successor->key = node.key;
        successor->port = node.port;
        predecessor->key = node.key;
        predecessor->port = node.port;
	}
	else{

		parse = strtok(NULL, token);
		clientfd = atoi(parse);
		listen_func(clientfd);
	}

	int sock;
	int connfd;
	socklen_t sockLen;
	struct sockaddr_in my_addr;
	struct sockaddr_in client_addr;
	pthread_t tid;

	memset((char*)&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_addr.s_addr = INADDR_ANY;
	my_addr.sin_port = htons(node.port);

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		perror("Socket creat failed: ");
		return 1;
	}
	if((bind(sock, (struct sockaddr *)&my_addr, sizeof(my_addr))) < 0){
		perror("Bind failed: ");
		return 1;
	}
	if(listen(sock, 5) < 0){
		perror("Listen failed: ");
		return 1;
	}
    
	pthread_create(&tid,NULL,finger_table_update,NULL);
	pthread_create(&tid,NULL,print_func,NULL);
	pthread_create(&tid,NULL,read_input,NULL);

    while(1){
    	if((connfd=accept(sock, (struct sockaddr *)&client_addr, &sockLen)) < 0){
    		perror("Accept failed: ");
    		continue;
    	}
    	int* sockpointer;
    	sockpointer=(int*)malloc(sizeof(int));
    	*sockpointer=connfd;
    	pthread_create(&tid,NULL,join_node,(void*)sockpointer);
    	pthread_join(tid,&self);
	}

	return 0;
}
