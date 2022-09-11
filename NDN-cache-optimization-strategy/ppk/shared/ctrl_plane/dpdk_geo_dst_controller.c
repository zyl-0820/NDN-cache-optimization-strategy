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


void fill_geo_ternary_table(uint8_t ip2[4],uint8_t mask[4],uint8_t dstmac[6],uint8_t port)
{
    char buffer[2048]; /* TODO: ugly */
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap,*ap2;
    struct p4_field_match_ternary* ternary;
    FILE *fp6;
    // fp6 = fopen("/home/it-34/log/geo_log2.txt","a");
    //     if(fp6){
	// 			fprintf(fp6,"geo:{%d}{%d}{%d}{%d},{%d}{%d}{%d}{%d}",ip2[0],ip2[1],ip2[2],ip2[3],mask[0],mask[1],mask[2],mask[3]);
    //             fprintf(fp6,"\n");
    //             fclose(fp6);
    //         }

    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "MyIngress.geo_ternary_0");

    ternary = add_p4_field_match_ternary(te, 2048);
    strcpy(ternary->header.name, "geo.dstAddr");
    memcpy(ternary->bitmap, ip2, 4);
    memcpy(ternary->mask, mask, 4);
    //ternary->length = sizeof(mask);

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "MyIngress.geo_forward");

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

    // ap3 = add_p4_action_parameter(h,a,2048);
    // strcpy(ap3->name,"ttl");
    // memcpy(ap3->bitmap,&ttl,4);
    // ap3->length = 4*8+0;


    printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_ternary(ternary);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
    netconv_p4_action_parameter(ap2);

    send_p4_msg(c, buffer, 2048);
    usleep(1200);

}


void set_default_action_geo_ternary()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;


    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "geo_ternary_0");

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
	uint8_t ip[4] = {10,0,99,99};
	uint8_t ip2[4] = {10,0,98,98};
	uint8_t ipv6[8] = {};
    uint8_t mask[4] = {255,255,255,255};
    uint8_t dstmac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
	uint8_t port = 1;
    // uint8_t ttl = 0;
    // uint8_t hoplimit = 0;

	fill_geo_ternary_table(ip2,mask,dstmac,port);
}


int read_config_from_file(char *filename)
{
	char line[100];
	uint8_t ip[4];
    uint8_t ip2[4];
	uint8_t ipv6[8];
    // int n = -1;
	uint8_t port;
    uint8_t prefix;
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
		if (line[0] == 'G'){
			if (16 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd.%hhd.%hhd.%hhd %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhd",
				&dummy,&ip2[0],&ip2[1],&ip2[2],&ip2[3],&mask[0],&mask[1],&mask[2],&mask[3],&dstmac[0],&dstmac[1],&dstmac[2],&dstmac[3],&dstmac[4],&dstmac[5],&port))
			{
                //  fp3 = fopen("/home/it-34/log/geo_log.txt","a");
                //  if(fp3){
				//      fprintf(fp3,"geo:{%d}{%d}{%d}{%d},{%d}{%d}{%d}{%d},{%d}{%d}{%d}{%d}{%d}{%d}",ip2[0],ip2[1],ip2[2],ip2[3],mask[0],mask[1],mask[2],mask[3],dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
                //      fprintf(fp3,"\n");
                //      fclose(fp3);
                //  }
				fill_geo_ternary_table(ip2,mask,dstmac,port);
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
	set_default_action_geo_ternary();

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
