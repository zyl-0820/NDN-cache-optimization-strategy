#include "controller.h"
#include "messages.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_IPS 60000
extern int usleep(__useconds_t usec);
extern void notify_controller_initialized();
FILE *fp6;

controller c;

void fill_dest_guid_exact_table(uint8_t dest_guid[4],uint8_t nxtHopMac[6],uint8_t port)
{
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap,*ap2;
    struct p4_field_match_exact* exact;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "MyIngress.dest_guid_exact_0");

    //  FILE *fp6;
    //  fp6 = fopen("/home/it-34/log/l3dst_ip_log.txt","a");
    //      if(fp6){
	//  	 fprintf(fp6,"ipv4:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",nxtHopMac[0],nxtHopMac[1],nxtHopMac[2],nxtHopMac[3],nxtHopMac[4],nxtHopMac[5],dest_guid[6],dest_guid[7]);
    //              fprintf(fp6,"\n");
    //              fclose(fp6);
    //          }

    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "mf.dest_guid");
    memcpy(exact->bitmap, dest_guid, 4);
    exact->length = 4*8+0;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "MyIngress.dest_guid_forward");

    ap = add_p4_action_parameter(h,a,2048);
    strcpy(ap->name,"nxtHopMac");
    memcpy(ap->bitmap,nxtHopMac,6);
    ap->length = 6*8+0;

    ap2 = add_p4_action_parameter(h, a, 2048);
    strcpy(ap2->name, "port");
    memcpy(ap2->bitmap, &port, 1);
    // ap2->bitmap = port;
    // ap2->bitmap[1] = 0;
    ap2->length = 1*8+1;

    printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
    netconv_p4_action_parameter(ap2);
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}



void dhf(void* b) {
       printf("Unknown digest received\n");
}


int read_config_from_file(char *filename)
{
	char line[100];
	// uint8_t ip[4];
    // int n = -1;
    uint8_t dest_guid[4];
	uint8_t port;
    uint8_t nxtHopMac[6];
    // uint8_t dstmac[6];
	char dummy;
    FILE *fp6;
	FILE *f;
	f = fopen(filename,"r");
	if (f == NULL) return -1;


	int line_index = 0;
	while (fgets(line,sizeof(line),f)){

		line[strlen(line)-1] = '\0';
		line_index++;
		printf("Sor:%d.",line_index);
		if(line[0] == 'M'){

			if (12 == sscanf(line,"%c %hhx %hhx %hhx %hhx %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhd",
				&dummy,&dest_guid[0],&dest_guid[1],&dest_guid[2],&dest_guid[3],&nxtHopMac[0],&nxtHopMac[1],&nxtHopMac[2],&nxtHopMac[3],&nxtHopMac[4],&nxtHopMac[5],&port))
			{
				fill_dest_guid_exact_table(dest_guid,nxtHopMac,port);
			}
			else{
                fclose(f);
                return -1;
			}
		}

	}
	fclose(f);
	return 0;
}


char* fn;
void init_complex(){

	if (read_config_from_file(fn)<0) {

    }
}


int main(int argc, char* argv[])
{
    // fp6 = fopen("/home/it-34/log/l3dst_ip_log.txt","a");
    //      if(fp6){
	//  	 fprintf(fp6,"diaoyong");
    //              fprintf(fp6,"\n");
    //              fclose(fp6);
    //          }
	if (argc>1) {
		if (argc!=2) {
			return -1;
		}
        fn = argv[1];
		c = create_controller_with_init(11111, 3, dhf, init_complex);
	}
    notify_controller_initialized();

	execute_controller(c);

	destroy_controller(c);

	return 0;
}
