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

controller c;


void fill_ipv6_exact_table(uint8_t ipv6[8],uint8_t dstmac[6],uint8_t port)
{
    char buffer[2048]; /* TODO: ugly */
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap,*ap2;
    struct p4_field_match_exact* exact;
    FILE *fp6;
    fp6 = fopen("/home/zhaoxin/log/ipv6_log2.txt","a");
         if(fp6){
				fprintf(fp6,"ipv6:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",ipv6[0],ipv6[1],ipv6[2],ipv6[3],ipv6[4],ipv6[5],ipv6[6],ipv6[7]);
                 fprintf(fp6,"\n");
                 fclose(fp6);
             }

    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "MyIngress.ipv6_exact_0");

    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"ipv6.dstAddr");
    memcpy(exact->bitmap,ipv6,16);
    exact->length = 8*16+0;

    a = add_p4_action(h,2048);
    strcpy(a->description.name,"MyIngress.ipv6_forward");

    // ap = add_p4_action_parameter(h,a,2048);
    // strcpy(ap->name,"dstAddr");
    // memcpy(ap->bitmap, dstAddr, 6);
    // ap->length = 6*8+0;

    ap = add_p4_action_parameter(h,a,2048);
    strcpy(ap->name,"dstmac");
    memcpy(ap->bitmap,dstmac,6);
    ap->length = 6*8+0;

    ap2 = add_p4_action_parameter(h, a, 2048);
    strcpy(ap2->name, "port");
    memcpy(ap2->bitmap, &port, 1);
    // ap2->bitmap = port;
    // ap2->bitmap[1] = 0;
    ap2->length = 1*8+1;

    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
    netconv_p4_action_parameter(ap2);
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}


void set_default_action_ipv6_exact()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;


    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "ipv6_exact_0");

    a = &(sda->action);
    strcpy(a->description.name, "_drop");

    netconv_p4_header(h);
    netconv_p4_set_default_action(sda);
    netconv_p4_action(a);

    send_p4_msg(c, buffer, sizeof(buffer));
}

void dhf(void* b) {
       printf("Unknown digest received\n");
}

void init_simple() {
	uint8_t ipv6[8] = {};
    uint8_t mask[4] = {255,255,255,255};
    uint8_t dstmac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
	uint8_t port = 1;
    // uint8_t ttl = 0;
    // uint8_t hoplimit = 0;

	fill_ipv6_exact_table(ipv6,dstmac,port);
}


int read_config_from_file(char *filename)
{
	char line[100];
	uint8_t ipv6[8];
    // int n = -1;
	uint8_t port;
	uint8_t mask[4];
    uint8_t dstmac[6];
    // uint8_t ttl;
    // uint8_t hoplimit;
	char dummy;
    // FILE *fp;
    FILE *fp3;
	FILE *f;
	f = fopen(filename,"r");
	if (f == NULL) return -1;

	int line_index = 0;
	while (fgets(line,sizeof(line),f)){
		line[strlen(line)-1] = '\0';
		line_index++;
		printf("Sor:%d.",line_index);
		if (line[0] == 'S'){
			if(24 == sscanf(line,"%c %2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhd",&dummy,&ipv6[0],&ipv6[1],&ipv6[2],&ipv6[3],&ipv6[4],&ipv6[5],&ipv6[6],&ipv6[7],&ipv6[8],&ipv6[9],&ipv6[10],&ipv6[11],&ipv6[12],&ipv6[13],&ipv6[14],&ipv6[15],&dstmac[0],&dstmac[1],&dstmac[2],&dstmac[3],&dstmac[4],&dstmac[5],&port))
			{
				fill_ipv6_exact_table(ipv6,dstmac,port);
			}
			else{
                fclose(f);
                return -1;
			}
		}
		else{
                fclose(f);
                return -1;
		}
	}
	fclose(f);
	return 0;
}

char* fn;
void init_complex(){
	set_default_action_ipv6_exact();

	if (read_config_from_file(fn)<0) {
    }
}

int main(int argc, char* argv[])
{

	if (argc>1) {
		if (argc!=2) {
			return -1;
		}
        fn = argv[1];
		c = create_controller_with_init(11111, 3, dhf, init_complex);
	}
	else {
		c = create_controller_with_init(11111, 3, dhf, init_simple);
	}

    notify_controller_initialized();

	execute_controller(c);

	destroy_controller(c);

	return 0;
}
