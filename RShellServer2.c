/*
 *   RShellServer1.c	example program for CS 468
 */


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
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/errno.h>

// Definitions for message type
#define RSHELL_REQ 0x11
#define AUTH_REQ 0x12
#define AUTH_RESP 0x13
#define AUTH_SUCCESS 0x14
#define AUTH_FAIL 0x15
#define RSHELL_RESULT 0x16

// Size in bytes of Message type
#define TYPESIZE 1

 // Size in bytes of Message payload length
#define LENSIZE 2

// Password size (in Hex)--> 20 bytes, 2 chars rep 1 byte, so 40 chars
#define PASSWDSIZE 40

// Max ID size: 16 - 1 = 15 bytes for id, 1 for null term
#define IDSIZE 16

// Max length of payload (2^16) = 65536
#define MAXPLSIZE 65536

// Max potential message size (2^1) + (2^2) + (2^16)
#define MAXMSGSIZE 65542

// Command size- sub
#define MAXBUFSIZE ((MAXPLSIZE - IDSIZE) - 1)

// provided code definitions
#define LINELEN     (MAXBUFSIZE - 20)
#define BUFSZ       (MAXBUFSIZE - 20)
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
            printf("Received AUTH_REQ message.\n");
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
    printf("MESSAGE--> TYPE:0x0%d   PAYLEN:%d  ID:%s   PAYLOAD:%s\n\n", msg->msgtype, msg->paylen, msg->id, msg->payload);
}


int
serversock(int UDPorTCP, int portN, int qlen)
{
    struct sockaddr_in svr_addr;    /* my server endpoint address       */
    int    sock;            /* socket descriptor to be allocated    */

    if (portN<0 || portN>65535 || qlen<0)   /* sanity test of parameters */
        return -2;

    bzero((char *)&svr_addr, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = INADDR_ANY;

    /* Set destination port number */
    svr_addr.sin_port = htons(portN);

    /* Allocate a socket */
    sock = socket(PF_INET, UDPorTCP, 0);
    if (sock < 0)
        return -3;

    /* Bind the socket */
    if (bind(sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0)
        return -4;

    if (UDPorTCP == SOCK_STREAM && listen(sock, qlen) < 0)
        return -5;

    return sock;
}

inline int serverTCPsock(int portN, int qlen)
{
  return serversock(SOCK_STREAM, portN, qlen);
}

inline int serverUDPsock(int portN)
{
  return serversock(SOCK_DGRAM, portN, 0);
}

void usage(char *self)
{
    // Useage message when bad # of arguments
    fprintf(stderr, "Usage: %s <port to run server on> <password file> \n", self);
    exit(1);
}

void errmesg(char *msg)
{
    fprintf(stderr, "**** %s\n", msg);
    exit(1);

}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */
void
reaper(int signum)
{
/*
    union wait  status;
*/

    int status;

    while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0)
        /* empty */;
}

/*------------------------------------------------------------------------
 *  This is a very simplified remote shell, there are some shell command it
    can not handle properly:

    cd
 *------------------------------------------------------------------------
 */
int
RemoteShellD(int sock)
{
    char cmd[BUFSZ+20];
    char result[resultSz];
    int cc, len;
    int rc=0;
    FILE *fp;


    printf("***** RemoteShellD(sock=%d) called\n", sock);


    while ((cc = read(sock, cmd, BUFSZ)) > 0)   /* received something */
    {

        if (cmd[cc-1]=='\n')
            cmd[cc-1]=0;
        else cmd[cc] = 0;


        printf("***** RemoteShellD(%d): received %d bytes: `%s`\n", sock, cc, cmd);


        strcat(cmd, " 2>&1");

    printf("***** cmd: `%s`\n", cmd);

        if ((fp=popen(cmd, "r"))==NULL) /* stream open failed */
            return -1;

        /* stream open successful */

        while ((fgets(result, resultSz, fp)) != NULL)   /* got execution result */
        {
            len = strlen(result);
            printf("***** sending %d bytes result to client: \n`%s` \n", len, result);

            if (write(sock, result, len) < 0)
            { rc=-1;
              break;
            }
        }
        fclose(fp);

    }

    if (cc < 0)
        return -1;

    return rc;
}

// Modified Remote Shell method, builds message for remote shell command
Message * MsgRemoteShell(char *command, char *id){
    char result[resultSz];
    FILE *fp;

    memset(result, 0, resultSz);

    Message *msg = (Message*)(malloc(sizeof(Message)));

    if ((fp = popen(command, "r")) == NULL){
        /* stream open failed */
        return NULL;
    }

    printf("");

    // Combine stderr and stdout in command
    strcat(command, " 2>&1");

    // read result of execution
    fread(result, resultSz, 1, fp); 

    // close file
    pclose(fp);

    // null term result
    result[strlen(result) - 1] = '\0';

    // Set message type
    msg->msgtype = RSHELL_RESULT;
    // Set payload length 16 for id
    msg->paylen = IDSIZE + strlen(result);
    // Set 16 byte id, 15 bytes for user ID max
    memcpy(msg->id,id,(IDSIZE - 1));
    // Ensure the user ID is null-terminated
    msg->id[strlen(id)] = '\0';
    msg->payload = result;

    printf("The result from command '%s' was:\n%s\n\n", command, result);

    return msg;
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
    if(msg->paylen > IDSIZE + 1){
        if ( (n = write(sock, msg->payload, (msg->paylen - IDSIZE) )) != (msg->paylen - IDSIZE) ){
            printf("ERROR: Has %d byte send when trying to send %d bytes for Message UserID: `%s`\n", n, (msg->paylen - IDSIZE), &msg);
            close(sock);
            return -1;
        }
    }

    return 0;
}



// Reads message from socket, returns NULL if there is an error during read
Message * read_message(int sock){
    // Create pointer to hold in the message read-in
    Message *msg = (Message*)(malloc(sizeof(Message)));

    // Read the message type
    if (read(sock, &msg->msgtype, TYPESIZE) != TYPESIZE){
        // Return NULL if there is an error
        // printf("ERROR: Could not read message type.\n");
        // Will reach here when client disconects.
        printf("Client has disconnected from the Server.\n"); 

        // Free memory
        free(msg);
        // Return NULL b/c of error
        return NULL;
    }

    // Read the message length
    if (read(sock, &msg->paylen, LENSIZE) != LENSIZE){
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
        if ( (read(sock, &msg->id, IDSIZE)) != IDSIZE ){
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
        if ( (read(sock, msg->payload, (msg->paylen - IDSIZE) )) != (msg->paylen - IDSIZE) ){
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



/*-------------------------------------------------------------------------------
 * Method to Authenticate sent client information with user/pass in password file
 *------------------------------------------------------------------------------*/

// Simple function for authentication
// Takes Client username, SHA1 hashed client password and compares to
// Server username and server SHA1 hashed password (read in from password file)
unsigned char * authenticate (char cluser[], char *pwdfname){
    char *seruser;
    unsigned char *serpass;
    char svruser[sizeof(cluser)];
    char svrpass[sizeof(clpass)];
    FILE *passwdfile;
    char *line = NULL;
    size_t linelen = 0;
    ssize_t read;
    passwdfile = fopen(pwdfname, "r");
    if (passwdfile == 0){
        printf("The specified password file was not found or could not be opened.\n");
        exit(1);
    }else{
        read = getline(&line, &linelen, passwdfile);
        fclose(passwdfile);
        char* linebuf;
        linebuf = strtok(line, ";");
        memcpy(&seruser, &linebuf, sizeof(seruser));
        linebuf = strtok(NULL, ";");
        while(isspace(*linebuf)){
            linebuf++;
        }
        linebuf = strtok(linebuf, "\n");
        memcpy(&serpass, &linebuf, sizeof(serpass));
        if(strcmp(cluser, seruser) == 0){
		return serpass;
	}
	else
	       printf("Invalid ID: %s\n\n", cluser);
	}
    
    // Free the line
    free(line);
    // Username or password did not match, so this is an AUTH_FAIL
    return -1;
}

int generateNonce()
 {
    srand(time(0));
    int x = rand() % 100 + 1;

   // printf("new rand = %d",x);
     return x;
   }
   //
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
 * main - Concurrent TCP server
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
    // Auth vars
    // server password file name (passed as a command line argument)
    char *passfname;

    // Command that the user wants to run on the RShell
    char *rshellcmd;

    // The message pointer
    Message *msg;

    // The user ID.
    char id[IDSIZE];


    // Variable that is true when the user is authenticated (successful login) or false if otherwise
    // After 60 seconds of authentication, should revert back to false
    bool auth = false;
    // Epoch times for calculatings 60 seconds past auth
    // Time of authentication
    struct timeval authtime;
    // Time of request for command
    struct timeval reqtime;

    // Can set and compare times with:
    /*
    gettimeofday(&authtime,NULL);
    gettimeofday(&reqtime,NULL);
    printf("SECONDS:%d\n", authtime.tv_sec);
    printf("SECONDS:%d\n", reqtime.tv_sec);
    */

    // Credentials sent by the client
    // Mock credentials sent by the client
    //char userid[] = "Alice";
    unsigned char mockpw[] = "0c8f72ea98dc74c71f9ff5bb72941036ae5120d9";

    //Var to hold hashed password from client
    unsigned char *password;

    // Server Vars
    int  msock;         /* master server socket     */
    int  ssock;         /* slave server socket      */
    int  portN;         /* port number to listen */
    struct sockaddr_in fromAddr;    /* the from address of a client */
    unsigned int  fromAddrLen;      /* from-address length          */
    int  prefixL, r;
    char *rec;

    // check for 3 args: program name and then: port num, password file
    if (argc == 3){
        // Set port number to run server on
        portN = atoi(argv[1]);
        // Set filename for password for to be used 
        passfname = argv[2];
    }else{
        // Show proper format
        usage(argv[0]);
    }

    msock = serverTCPsock(portN, 5);

    (void) signal(SIGCHLD, reaper);

    while (1) {
        fromAddrLen = sizeof(fromAddr);
        ssock = accept(msock, (struct sockaddr *)&fromAddr, &fromAddrLen);
        if (ssock < 0) {
            if (errno == EINTR)
                continue;
            errmesg("accept error\n");
        }

        switch (fork())
        {
            case 0:     /* child */
                close(msock);

                // Print new connection message
                printf("Client has connected to the Server.\n"); 

                // Listen for client message 
                while(msg = read_message(ssock)){
                    if(msg != NULL){
                        printf("Received Message from Client:\n");
                        print_message(msg);

                        gettimeofday(&reqtime,NULL);
                        // Set auth to false if have been authenticated for more than 60 seconds
                        // (Check time of requestion - time of authentication) > 60 seconds
                        if( (reqtime.tv_sec - authtime.tv_sec) > 60){
                            printf("More than 60 seconds have passed, setting user authentication to false.\n\n");
                            // Set auth to false
                            auth = false;
                        }

                        if(!auth){

                            // User hasn't been authenticated yet
                            switch(msg -> msgtype){
				 int nonce1,nonce2;
                                case RSHELL_REQ :
				     // Save request message
				    nonce1 = msg->payload;
				    // set nonce2 
				    nonce2 = generateNonce();
                                     Save the command the user wants to run
                                    rshellcmd = (char*)malloc( (msg->paylen - IDSIZE) * sizeof(char));
                                    memcpy(rshellcmd, msg->payload, strlen(msg->payload));
                                    Ensure null terminated command
                                    rshellcmd[(msg->paylen - IDSIZE) ] = '\0';
                                    printf("The RShell command the user wants to run is: %s\n\n", rshellcmd);
                                    
                                    // Copy the from the message into the server id field
                                    memcpy(id,msg->id,IDSIZE);
                                    // Ensure the user ID is null-terminated
                                    id[strlen(id)] = '\0';
                                    //printf("THE ID FROM THE CLIENT IS: %s\n", id);
                                    // Free the current message
                                    free(msg);

                                    // Create a an AUTH_REQ message
                                    msg = malloc(sizeof(Message));
                                    // Set message type
                                    msg->msgtype = AUTH_REQ;
                                    // Set payload length 16 for id
                                    msg->paylen = IDSIZE;
                                    // Set 16 byte id, 15 bytes for user ID max
                                    memcpy(msg->id,id,(IDSIZE - 1));
                                    // Ensure the user ID is null-terminated
                                    msg->id[strlen(id)] = '\0';
                                    // Don't need to set a payload for this message
                                    msg->payload = nonce2;

                                    // Write the AUTH REQ MESSAGE
                                    printf("Sending the following Message from Server to Client:\n");
                                    print_message(msg);
                                    write_message(ssock, msg);
                                    break;
                                case AUTH_RESP :
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
        int noncelength  = sizeof(int) + 1;
	res = AES256_CBC_Decryption(msg->payload,KEY, IV, &msg->paylen);	
	int  cnonce = 0,count=0;
	for(i=0;i<strlen(res);i++){
	   if(isdigit(res[i]))
               count++;
	}
	count=count-1;
        for (i = 0; i < count ; i++)
        	cnonce =cnonce + ((res[count-(i + 1)]-'0') * pow(10, i));

				    //Save the command the user wants to run
                                    rshellcmd = (char*)malloc( (msg->paylen - IDSIZE) * sizeof(char));
                                    memcpy(rshellcmd, res+count, strlen(res));
                                    //Ensure null terminated command
                                    rshellcmd[strlen(rshellcmd)-1] = '\0';
                                    printf("The RShell command the user wants to run is: %s\n\n", rshellcmd);

		if(cnonce==nonce2+1){
			password = (char*)malloc( PASSWDSIZE * sizeof(char) + 1);
			password = authenticate (id, passfname);
			cipherText = AES256_CBC_Encryption((unsigned char *)AUTH_RESPONCE,KEY,IV,&noncelength);
					// Auth Success!!
                                        free(password);
                                        // set auth to true
                                        auth = true;
                                        // set time of authentication
                                        gettimeofday(&authtime,NULL);
                                        // Free the current message
                                        free(msg);

                                        // Create a an AUTH_SUC message
                                        msg = malloc(sizeof(Message));
                                        // Set message type
                                        msg->msgtype = AUTH_SUCCESS;
                                        // Set payload length 16 for id
                                        msg->paylen = IDSIZE;
                                        // Set 16 byte id, 15 bytes for user ID max
                                        memcpy(msg->id,id,(IDSIZE - 1));
                                        // Ensure the user ID is null-terminated
                                        msg->id[strlen(id)] = '\0';
                                        // Don't need to set a payload for this message
                                        msg->payload = cipherText;

                                        // Write the AUTH SUCCESS
                                        printf("Sending the following Message from Server to Client:\n");
                                        print_message(msg);
                                        write_message(ssock, msg);
                                        // Now I actually have to run the command

                                        /*
                                        RUN COMMAND AND RETURN RESULT START
                                        */

                                        free(msg);

                                        printf("The RShell command to be run on the Server is: %s\n\n", rshellcmd);

                                        // Create a an RSHELL_RESULT message
                                        msg = MsgRemoteShell(rshellcmd, id);
					
                                        // Write the RSHELL RESULT
                                        printf("Sending the following Message from Server to Client:\n");
                                        print_message(msg);
                                        write_message(ssock, msg);

                                        // Free the message
                                        free(msg);

                                        // Free rshellcmd
                                        free(rshellcmd);

                                        /*
                                        RUN COMMAND AND RETURN RESULT END
                                        */
                                        break;
                                    }else{
                                        // Auth fail
                                        free(password);
                                        auth = false;

                                        // Free the current message
                                        free(msg);
                                        // Create a an AUTH_SUC message
                                        msg = malloc(sizeof(Message));
                                        // Set message type
                                        msg->msgtype = AUTH_FAIL;
                                        // Set payload length 16 for id
                                        msg->paylen = IDSIZE;
                                        // Set 16 byte id, 15 bytes for user ID max
                                        memcpy(msg->id,id,(IDSIZE - 1));
                                        // Ensure the user ID is null-terminated
                                        msg->id[strlen(id)] = '\0';
                                        // Don't need to set a payload for this message
                                        msg->payload = '\0';

                                        // Write the AUTH FAIL
                                        printf("Sending the following Message from Server to Client:\n");
                                        print_message(msg);
                                        write_message(ssock, msg);
                                    }
                                    break;
                                default :
                                    printf("ERROR: Received Invalid message.\n");
                                    break;
                            }
                        }else{
                            // The user has already been authenticated, just run command
                            printf("The user %s has already been authenticated. Will run command.\n\n", id);
                            switch(msg -> msgtype){
                                case RSHELL_REQ :
                                    // Save the command the user wants to run
                                    rshellcmd = (char*)malloc( (msg->paylen - IDSIZE) * sizeof(char));
                                    memcpy(rshellcmd, msg->payload, strlen(msg->payload));
                                    // Ensure null terminated command
                                    rshellcmd[(msg->paylen - IDSIZE) ] = '\0';
                                    
                                    // Copy the from the message into the server id field
                                    memcpy(id,msg->id,IDSIZE);
                                    // Ensure the user ID is null-terminated
                                    id[strlen(id)] = '\0';
                                    //printf("THE ID FROM THE CLIENT IS: %s\n", id);
                                    // Free the current message
                                    free(msg);

                                    /*
                                    RUN COMMAND AND RETURN RESULT START
                                    */

                                    printf("The RShell command to be run on the Server is: %s\n\n", rshellcmd);

                                    // Create a an RSHELL_RESULT message
                                    msg = MsgRemoteShell(rshellcmd, id);

                                    // Write the RSHELL RESULT
                                    printf("Sending the following Message from Server to Client:\n");
                                    print_message(msg);
                                    write_message(ssock, msg);

                                    // Free the message
                                    free(msg);

                                    // Free rshellcmd
                                    free(rshellcmd);

                                    /*
                                    RUN COMMAND AND RETURN RESULT END
                                    */
                                    break;
                                default :
                                    printf("ERROR: Received Invalid message.\n");
                                    break;
                            }
                        }
                    }
                }
                close(ssock);
                exit(r);

            default:    /* parent */
                (void) close(ssock);
                break;
            case -1:
                errmesg("fork error\n");
        }
    }
    close(msock);
}
