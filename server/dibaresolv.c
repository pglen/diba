

#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <errno.h> 
#include <netdb.h> 
#include <arpa/inet.h>
#include <netinet/in.h>

//  Get ip from domain name
 
int     hostname_to_ip(char *hostname, char *ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
         
    if ( (he = gethostbyname( hostname ) ) == NULL) 
        {
        // get the host info
        //herror("gethostbyname");
        return -1;
        }
 
    addr_list = (struct in_addr **) he->h_addr_list;
     
    for(i = 0; addr_list[i] != NULL; i++) 
        {
        //Return the first one;
        if(i == 0)
            strcpy(ip, inet_ntoa(*addr_list[i]) );
        
        printf("'%s' ", inet_ntoa(*addr_list[i]));
        }
    printf("\n");     
    return 0;  
}

int main(int argc, char *argv[])

{
    char ip[24];
    //printf("Resolver\n");
    
    char *hostname = argv[1];
    if(hostname == NULL)
        {
        printf("Use: %s hostname\n", argv[0]);
        return 2;
        } 
    int ret = hostname_to_ip(hostname , ip);
    if(ret < 0)
        {
        printf("Cannot resolve: '%s'\n", hostname);
        return 1;
        }
    printf("'%s' resolved to '%s'" , hostname , ip);
    
    return 0;
}

