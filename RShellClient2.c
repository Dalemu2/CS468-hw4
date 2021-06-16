
// OpenSSL Imports
#include <openssl/sha.h>
#include <time.h>
#include <stdbool.h>

// Other Imports
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/errno.h>

// Definitions for message type
#define RSHELL_REQ 0x11
#define AUTH_CHLG 0x12
#define AUTH_RESP 0x13
#define AUTH_SUCCESS 0x14
#define AUTH_FAIL 0x15
#define RSHELL_RESULT 0x16

// Size in bytes of Message type
#define TYPESIZE 1

 // Size in bytes of Message payload length
#define LENSIZE 2

// Max ID size: 16 - 1 = 15 bytes for id, 1 for null term
#define IDSIZE 16

// Password size (in Hex)--> 20 bytes, 2 chars rep 1 byte, so 40 chars
#define PASSWDSIZE 40

// Max length of payload (2^16) = 65536
#define MAXPLSIZE 65536

// Max potential message size (2^1) + (2^2) + (2^16)
#define MAXMSGSIZE 65542

// Command size
#define MAXBUFSIZE ((MAXPLSIZE - IDSIZE) - 1)

// provided code definitions
#define LINELEN     MAXBUFSIZE
#define BUFSZ       MAXBUFSIZE
#define resultSz    (MAXPLSIZE - 1)


// Typedef for the message format
typedef struct Message{
	// Message type
	char msgtype;
	// payload length in bytes
	short paylen;
	// id for the first 16 bytes of the payload
	char id[IDSIZE];
	// the payload
        char *payload;
}Message;

// Method to determine the message type.
int decode_type(Message *msg){
    switch(msg -> msgtype){
        case RSHELL_REQ :
            printf("Received RSHELL_REQ message.\n");
            return 1;
            break;
        case AUTH_CHLG :
            printf("Received AUTH_CHLG message.\n");
            return 2;
            break;
        case AUTH_RESP :
            printf("Received AUTH_RESP message.\n");
            return 3;
            break;
        case AUTH_SUCCESS :
            printf("Received AUTH_SUCCESS message.\n");
            return 4;
            break;
        case AUTH_FAIL :
            printf("Received AUTH_FAIL message.\n");
            return 5;
            break;
        case RSHELL_RESULT :
            printf("Received RSHELL_RESULT message.\n");
            return 6;
            break;
        default :
            printf("ERROR: Received Invalid message.\n");
            return -1;
            break;
    }
}

// Debug method to print a Message
void print_message(Message *msg){
	printf("MESSAGE--> TYPE:0x0%d   PAYLEN:%d  ID:%s   PAYLOAD:%s	NONCE1:%d\n\n", msg->msgtype, msg->paylen, msg->id, msg->payload);
}

int
clientsock(int UDPorTCP, const char *destination, int portN)
{
	struct hostent	*phe;		/* pointer to host information entry	*/
	struct sockaddr_in dest_addr;	/* destination endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/


	bzero((char *)&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;

    /* Set destination port number */
	dest_addr.sin_port = htons(portN);

    /* Map host name to IPv4 address, does not work well for IPv6 */
	if ( (phe = gethostbyname(destination)) != 0 )
		bcopy(phe->h_addr, (char *)&dest_addr.sin_addr, phe->h_length);
	else if (inet_aton(destination, &(dest_addr.sin_addr))==0) /* invalid destination address */
		return -2;

/* version that support IPv6
	else if (inet_pton(AF_INET, destination, &(dest_addr.sin_addr)) != 1)
*/

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Connect the socket */
	if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
		return -4;

	return sock;
}

inline int clientTCPsock(const char *destination, int portN)
{
  return clientsock(SOCK_STREAM, destination, portN);
}


inline int clientUDPsock(const char *destination, int portN)
{
  return clientsock(SOCK_DGRAM, destination, portN);
}


void usage(char *self)
{
	// Useage message when bad # of arguments
	fprintf(stderr, "Usage: %s <server IP> <server port number> <ID> <password> \n", self);
	exit(1);
}

void errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------------
 * TCPrecv - read TCP socket sock w/ flag for up to buflen bytes into buf

 * return:
	>=0: number of bytes read
	<0: error
 *------------------------------------------------------------------------------
 */
int
TCPrecv(int sock, char *buf, int buflen, int flag)
{
	int inbytes, n;

	if (buflen <= 0) return 0;

  /* first recv could be blocking */
	inbytes = 0;
	n=recv(sock, &buf[inbytes], buflen - inbytes, flag);
	if (n<=0 && n != EINTR)
		return n;

	buf[n] = 0;


	printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): first read %d bytes : `%s`\n",
			   sock, buflen, flag, n, buf);

  /* subsequent tries for for anything left available */

	for (inbytes += n; inbytes < buflen; inbytes += n)
	{
	 	if (recv(sock, &buf[inbytes], buflen - inbytes, MSG_PEEK|MSG_DONTWAIT)<=0) /* no more to recv */
			break;
	 	n=recv(sock, &buf[inbytes], buflen - inbytes, MSG_DONTWAIT);
		buf[n] = 0;


		printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): subsequent read %d bytes : `%s`\n",
			   sock, buflen, flag, n, &buf[inbytes]);


	  if (n<=0) /* no more bytes to receive */
		break;
	};


		printf("\tTCPrecv(sock=%d, buflen=%d): read totally %d bytes : `%s`\n",
			   sock, buflen, inbytes, buf);


	return inbytes;
}

int
RemoteShell(char *destination, int portN)
{
	char	buf[LINELEN+1];		/* buffer for one line of text	*/
	char	result[resultSz+1];
	int	sock;				/* socket descriptor, read count*/


	int	outchars, inchars;	/* characters sent and received	*/
	int n;

	if ((sock = clientTCPsock(destination, portN)) < 0)
		errmesg("fail to obtain TCP socket");

	while (fgets(buf, sizeof(buf), stdin))
	{
		buf[LINELEN] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(buf);
		if ((n=write(sock, buf, outchars))!=outchars)	/* send error */
		{

			printf("RemoteShell(%s, %d): has %d byte send when trying to send %d bytes to RemoteShell: `%s`\n",
			   destination, portN, n, outchars, buf);

			close(sock);
			return -1;
		}

		printf("RemoteShell(%s, %d): sent %d bytes to RemoteShell: `%s`\n",
			   destination, portN, n, buf);


		/* Get the result */

		if ((inchars=recv(sock, result, resultSz, 0))>0) /* got some result */
		{
			result[inchars]=0;
			fputs(result, stdout);
		}
		if (inchars < 0)
				errmesg("socket read failed\n");
	}

	close(sock);
	return 0;
}

// Writes messages to socket: Returns 0 if successful, 1 if there was an error
int write_message(int sock, Message *msg){
    // Size will be the message type + paylen + ID + payload
    int msgsize = sizeof(char) + sizeof(short) + (sizeof(char) * msg->paylen);
    // n will store return value of write()
	int n;

    //printf("The size of the message you are sending is: %d\n", msgsize);

    // Write the message type
    if ( (n = write(sock, &msg->msgtype, TYPESIZE)) != TYPESIZE ){
        printf("ERROR: Has %d byte send when trying to send %d bytes for Message Type: `%s`\n", n, TYPESIZE, &msg);
        close(sock);
        return -1;
    }

    // Write the message length
    if ( (n = write(sock, &msg->paylen, LENSIZE)) != LENSIZE ){
        printf("ERROR: Has %d byte send when trying to send %d bytes for Message Length: `%s`\n", n, LENSIZE, &msg);
        close(sock);
        return -1;
    }

    // Write the user ID
    if(msg->paylen >= IDSIZE){
    	if ( (n = write(sock, &msg->id, IDSIZE)) != IDSIZE ){
        	printf("ERROR: Has %d byte send when trying to send %d bytes for Message UserID: `%s`\n", n, IDSIZE, &msg);
        	close(sock);
        	return -1;
    	}
    }

    // Write the payload, check IDSIZE + 1 for null term
    if(msg->paylen > IDSIZE){
    	if ( (n = write(sock, msg->payload, (msg->paylen - IDSIZE) )) != (msg->paylen - IDSIZE) ){
        	printf("ERROR: Has %d byte send when trying to send %d bytes for Message UserID: `%s`\n", n, (msg->paylen - IDSIZE), &msg);
        	close(sock);
        	return -1;
    	}
    }

	return 0;
}


// Recv message from socket, returns NULL if there is an error during read
Message * recv_message(int sock){
	// Create pointer to hold in the message read-in
	Message *msg = (Message*)(malloc(sizeof(Message)));

	// Read the message type
	if (recv(sock, &msg->msgtype, TYPESIZE, 0) != TYPESIZE){
		// Return NULL if there is an error
		printf("ERROR: Could not read message type.\n");
		// Free memory
		free(msg);
		// Return NULL b/c of error
		return NULL;
	}

	// Read the message length
	if (recv(sock, &msg->paylen, LENSIZE, 0) != LENSIZE){
		// Return NULL if there is an error
		printf("ERROR: Could not read message length.\n");
		// Free memory
		free(msg);
		// Return NULL b/c of error
		return NULL;
	}

    // Check if 16 bytes of ID exists
    if(msg->paylen >= IDSIZE){
    	// Write the user ID
    	if ( (recv(sock, &msg->id, IDSIZE, 0)) != IDSIZE ){
        	printf("ERROR: Could not read message ID.\n");
			// Free memory
			free(msg);
			// Return NULL b/c of error
			return NULL;
    	}
    }

    // Check if more 16 bytes of length exist, b/c first 16 is ID, the rest would be payload...
    if(msg->paylen > IDSIZE){
    	// Need to malloc new memory for the incoming payload
    	// The size is the payload size described in the message - the ID bytes
    	msg->payload = (char*)malloc( (msg->paylen - IDSIZE) * sizeof(char));
    	// Write the payload
    	if ( (recv(sock, msg->payload, (msg->paylen - IDSIZE), 0)) != (msg->paylen - IDSIZE) ){
        	printf("ERROR: Could not read message payload.\n");
        	// Free memory
			free(msg);
			// Return NULL b/c of error
			return NULL;
    	}
    }

    // Return pointer to read-in message
	return msg;
}
// NONCE generator 
int generateNonce()
 {
    srand(time(0));
    int x = rand() % 100 + 1;
    
   // printf("new rand = %d",x);
    return x;
}
unsigned char *AES256_CBC_Encryption(unsigned char *text,char *key, char *iv,int *length){

         int cipherLength = *length;
        int tmplen;

        unsigned char *cipherText = malloc(cipherLength);

        EVP_CIPHER_CTX encrypt;         //initialize
        EVP_CIPHER_CTX_init(&encrypt);

        EVP_EncryptInit_ex(&encrypt, EVP_aes_256_cbc(), NULL, key, iv); //sets up cipher context ctx for encryption with cipher type
        EVP_EncryptUpdate(&encrypt, cipherText, &cipherLength, text,*length);// encrypts inl bytes from the buffer in and writes the encrypted version to out.
        EVP_EncryptFinal_ex(&encrypt, cipherText + cipherLength , &tmplen);//will not encrypt any more data and it will return an error if any data remains in a partial block
        EVP_CIPHER_CTX_cleanup(&encrypt);       // clears all information from a cipher context and free up any allocated memory
       *length = cipherLength + tmplen;
        return cipherText;
}

unsigned char *AES256_CBC_Decryption(unsigned char *cText,char *key , char *iv, int *length){

        int pTextLength = *length;
        int tmplen;

        unsigned char *pText = malloc(pTextLength);

        EVP_CIPHER_CTX dec;         //initialize
        EVP_CIPHER_CTX_init(&dec);

        EVP_DecryptInit_ex(&dec, EVP_aes_256_cbc(), NULL, key, iv); //sets up cipher context ctx for decryption with cipher type
        EVP_DecryptUpdate(&dec, pText, &pTextLength, cText,*length);// decrypts inl bytes from the buffer in and writes the decrypted version to out.
        EVP_DecryptFinal_ex(&dec,pText + pTextLength , &tmplen);//will not encrypt any more data and it will return an error if any data remains in a partial block
        EVP_CIPHER_CTX_cleanup(&dec);       // clears all information from a cipher context and free up any allocated memory
       *length = pTextLength + tmplen;
        return (char *)pText;
}

/*------------------------------------------------------------------------
 * main  *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	char *destination;
	int portN;
	char *userid;
 	unsigned char password[SHA_DIGEST_LENGTH * 2];
	unsigned char tmphash[SHA_DIGEST_LENGTH];
	
	char plainKEY[SHA_DIGEST_LENGTH * 3];
	unsigned char KEY[SHA256_DIGEST_LENGTH * 2];
	unsigned char KEYtemp[SHA256_DIGEST_LENGTH];

	unsigned char IV[SHA256_DIGEST_LENGTH * 2];
        unsigned char IVtemp[SHA256_DIGEST_LENGTH];
	
	
	char iv[2];

	unsigned char *cipherText;
    	char buf[MAXBUFSIZE + 1];
    	char id[IDSIZE];
	char AUTH_RESPONCE[MAXBUFSIZE + 5];
    	int inchars;
	char *SHELL_RESULT;
	Message *recvmsg;

	if (argc == 5){
		destination = argv[1];
		portN = atoi(argv[2]);
		userid = argv[3];
      		SHA_CTX ctx;
                SHA1_Init(&ctx);
                SHA1_Update(&ctx, argv[4], strlen( argv[4] ));
                SHA1_Final(tmphash, &ctx);
                int hctr = 0;
                for (hctr = 0; hctr < SHA_DIGEST_LENGTH; hctr++){
                     sprintf( ((unsigned char*) &(password[ hctr * 2 ])), "%02x", tmphash[ hctr ] );
                }
                printf("The password \"%s\" has a SHA1 hash of \"%s\".\n\n", argv[4], password);
                printf("Running Client with the following credentials...\n");
                printf("    Destination: %s\n    Port: %d\n    User_ID: %s\n    Hashed_Password: %s\n\n",destination,portN,userid,password);
	}
	else {
		usage(argv[0]);
	}
	int sock;
	if ((sock = clientTCPsock(destination, portN)) < 0){
		errmesg("Failed to obtain TCP socket.");
		exit(1);
	}
        Message *msg;
	Message *key;
while(1){
	int nonce1 = generateNonce();
	buf[0] = '\0';

	msg = malloc(sizeof(Message));
        msg->msgtype = 0x11;
	msg->paylen = IDSIZE + 1;
   	memcpy(msg->id,userid,(IDSIZE - 1));  
   	msg->id[strlen(userid)] = '\0';
   	msg->payload = nonce1;

   	printf("Sending the following Message from Client to Server:\n");
   	print_message(msg);
   	write_message(sock, msg);
   	
	recvmsg = recv_message(sock);
  	printf("Received Message from Server:\n");
   	print_message(recvmsg);
	
    	int nonce2 = recvmsg->payload;

	memcpy(plainKEY,password,SHA_DIGEST_LENGTH);
        snprintf(iv,sizeof(iv),"%d%d",nonce1,nonce2);
	strcat(plainKEY,iv);
	plainKEY[strlen(plainKEY)-1] = '\0';
	
	iv[strlen(iv)-1] = '\0';

	SHA256_CTX ctxIV;
	SHA256_Init(&ctxIV);
        SHA256_Update(&ctxIV,iv,strlen(iv));
        SHA256_Final(IVtemp, &ctxIV);

        int i = 0;
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++){
             sprintf( ((unsigned char*) &(IV[i * 2])), "%02x", IVtemp[i] );
        }
	
 	SHA256_CTX ctxKEY;
        SHA256_Init(&ctxKEY);
        SHA256_Update(&ctxKEY,plainKEY,strlen(plainKEY));
        SHA256_Final(KEYtemp, &ctxIV);

        for (i = 0; i < SHA256_DIGEST_LENGTH; i++){
             sprintf(((unsigned char*) &(KEY[i * 2])), "%02x", KEYtemp[i] );
        }
	int keyLength = strlen(KEY) + 1;
   	printf("Connection established. Type a command to run on the Remote Shell...\n");
	
   	switch(recvmsg -> msgtype){
		case AUTH_CHLG :
			// Create message for command AUTH_RESP
			free(msg);
   			fgets(buf, sizeof(buf), stdin);
   			if(strlen(buf) > 1){

				// Print newline after entered character
				printf("\n");
				// Ensure the buffer is null-terminated
				buf[strlen(buf) - 1] = '\0';
				// add nonce1
				snprintf(AUTH_RESPONCE,sizeof(AUTH_RESP),"%d",(nonce2+1));
				// concatnate nonce1  and shell command 
				strcat(AUTH_RESPONCE,buf);
				// ENSURE AUTH_RESP is null-terminated
				AUTH_RESPONCE[strlen(AUTH_RESPONCE)-1] = '\0';
				// Create message for command RSHELL_REQ
				msg = malloc(sizeof(Message));
				// create encription
				cipherText = malloc(sizeof(Message)); 
				// Set message type
				msg->msgtype = 0x13;
				// Set payload length 16 + buffer
				msg->paylen = IDSIZE + strlen(AUTH_RESPONCE) + 16 - (strlen(AUTH_RESPONCE)%16);
				// Set 16 byte id, 15 bytes for user ID max
				memcpy(msg->id,userid,(IDSIZE - 1));
				// Ensure the user ID is null-terminated
				msg->id[strlen(userid)] = '\0';
				int ARlength = strlen(AUTH_RESPONCE) + 1;
				cipherText = AES256_CBC_Encryption((unsigned char *)AUTH_RESPONCE,KEY,IV, &ARlength);
				// Set variable length Payload
				msg->payload = cipherText;


				// Free recvmsg
				free(recvmsg);

				// Send AUTH_RESP
				printf("Sending the following Message from Client to Server:\n");
				print_message(msg);
				write_message(sock, msg);


				// Wait for AUTH_SUCCESS / AUTH_FAIL 
				recvmsg = recv_message(sock);
				printf("Received Message from Server:\n");
				print_message(recvmsg);
				switch(recvmsg -> msgtype){
					case AUTH_SUCCESS :
						char res[recvmsg->paylen];
						 res = AES256_CBC_Decryption(recvmsg->payload,KEY, IV, &recvmsg->paylen);
						int  nonce = 0;
 						for (i = 0; i < recvmsg->paylen ; i++)
    						        nonce = nonce + ((res[recvmsg->paylen-(i + 1)]-'0') * pow(10, i));
    
						if(nonce == nonce+1){					
							printf("Authentication Success!\n");
						
							// Get the command exec result
							recvmsg = recv_message(sock);
							printf("Received Message from Server:\n");
							print_message(recvmsg);
							if(recvmsg -> msgtype == RSHELL_RESULT){
								// Got the result
								// decript the result and print
								if(recvmsg->payload != NULL){
									SHELL_RESULT = AES256_CBC_Decryption(recvmsg->payload,KEY, IV, &recvmsg->paylen);
									printf("\nThe result of the command was:\n%s\n\n",SHELL_RESULT);
								}
								else{
									// command not found
									printf("\nThe result of the command was:\ncommand not found\n\n");
								}
							}
							else{
								printf("ERROR: Received Invalid message.\n");
							}

							break;
					case AUTH_FAIL :
					   	// Free recvmsg
				    		free(recvmsg);
						printf("Authentication Failed!\n");
						exit(1);
						break;
					default :
						printf("ERROR: Received Invalid message.\n");
						break;
				}
				break;

			case RSHELL_RESULT :
				// Print the result
				if(recvmsg->payload != NULL){
					SHELL_RESULT = AES_CBC_Decryption(recvmsg->payload,KEY, IV, &recvmsg->paylen);
					printf("\nThe result of the command was:\n%s\n\n",SHELL_RESULT);
				}
				else{
					// command not found
						printf("\nThe result of the command was:\ncommand not found\n\n");
					}
					break;
				default :
					printf("ERROR: Received Invalid message.\n");
					break;
			}
			// Clear the buffer
		    buf[0] = '\0';
		    // Print seperating stars
		    printf("**********************************************************************\n\n");
		    // Ask for another command
		    printf("Type another command to run on the Remote Shell...\n");
		}else{
			// Quit program
			exit(0);
		}
	}



	// Terminate the program 
	exit(0);
}
