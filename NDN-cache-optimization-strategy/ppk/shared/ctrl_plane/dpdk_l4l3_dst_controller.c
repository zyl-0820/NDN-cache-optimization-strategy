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
FILE *fp3;

controller c;

void fill_ipv4_tcp_table(uint8_t ip[4],uint8_t prefix,uint8_t dstport,uint8_t port)
{
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap2;
    struct p4_field_match_lpm* lpm;
    struct p4_field_match_exact* exact;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "MyIngress.ipv4_tcp_0");

     FILE *fp6;
     /*fp6 = fopen("/home/zhaoxing/log/l4l3dst_ip&port.txt","a");
         if(fp6){
	 	 fprintf(fp6,"tcp_ip:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",ip[0],ip[1],ip[2],ip[3],ip[4],ip[5],ip[6],ip[7]);
                 fprintf(fp6,"\n");
                 fclose(fp6);
             }*/

    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"tcp.dstPort");
    memcpy(exact->bitmap,&dstport,2);
    exact->length = 8*2+0;

    lpm = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm->header.name, "ipv4.dstAddr");
    memcpy(lpm->bitmap, ip, 4);
    lpm->prefix_length = prefix;




    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "MyIngress.ipv4_forward");

    ap2 = add_p4_action_parameter(h, a, 2048);
    strcpy(ap2->name, "port");
    memcpy(ap2->bitmap, &port, 1);
    // ap2->bitmap = port;
    // ap2->bitmap[1] = 0;
    ap2->length = 1*8+1;

    //printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_field_match_lpm(lpm);

    netconv_p4_action(a);
    netconv_p4_action_parameter(ap2);
    
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}


void fill_ipv4_udp_table(uint8_t ip[4],uint8_t prefix,uint8_t dstport,uint8_t port)
{
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter *ap2;
    struct p4_field_match_lpm* lpm;
    struct p4_field_match_exact* exact;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "MyIngress.ipv4_udp_0");

     FILE *fp6;
     /*fp6 = fopen("/home/zhaoxing/log/l4l3dst_ip&port.txt","a");
         if(fp6){
	 	 fprintf(fp6,"udp_ip:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",ip[0],ip[1],ip[2],ip[3],ip[4],ip[5],ip[6],ip[7]);
                 fprintf(fp6,"\n");
                 fclose(fp6);
             }*/
    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"udp.dstPort");
    memcpy(exact->bitmap,&dstport,2);
    exact->length = 8*2+0;

    lpm = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm->header.name, "ipv4.dstAddr");
    memcpy(lpm->bitmap, ip, 4);
    lpm->prefix_length = prefix;



    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "MyIngress.ipv4_forward");

    ap2 = add_p4_action_parameter(h, a, 2048);
    strcpy(ap2->name, "port");
    memcpy(ap2->bitmap, &port, 1);
    // ap2->bitmap = port;
    // ap2->bitmap[1] = 0;
    ap2->length = 1*8+1;

    //printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_field_match_lpm(lpm);

    netconv_p4_action(a);
    netconv_p4_action_parameter(ap2);
    
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}


void set_default_action_ipv4_tcp()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;


    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "ipv4_tcp_0");

    a = &(sda->action);
    strcpy(a->description.name, "_drop");

    netconv_p4_header(h);
    netconv_p4_set_default_action(sda);
    netconv_p4_action(a);

    send_p4_msg(c, buffer, sizeof(buffer));
}


void set_default_action_ipv4_udp()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;


    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "ipv4_udp_0");

    a = &(sda->action);
    strcpy(a->description.name, "_drop");

    netconv_p4_header(h);
    netconv_p4_set_default_action(sda);
    netconv_p4_action(a);

    send_p4_msg(c, buffer, sizeof(buffer));
}

void dhf(void* b) {
       //printf("Unknown digest received\n");
}


int read_config_from_file(char *filename)
{
	char line[100];
	uint8_t ip[4];
    uint8_t ip2[4];
    // int n = -1;
	uint8_t port;
    uint8_t dstport;
    uint8_t prefix;
	char dummy;
    // FILE *fp3;
	FILE *f;
	f = fopen(filename,"r");
	if (f == NULL) return -1;

	int line_index = 0;
	while (fgets(line,sizeof(line),f)){
		line[strlen(line)-1] = '\0';
		line_index++;
		//printf("Sor:%d.",line_index);
		if(line[0] == 'E'){
			if (8 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd %hhd %hhd",
				&dummy,&ip[0],&ip[1],&ip[2],&ip[3],&prefix,&dstport,&port))
			{
				fill_ipv4_tcp_table(ip,prefix,dstport,port);
			}
			else{
                fclose(f);
                return -1;
			}
		}
        if(line[0] == 'R'){
			if (8 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd  %hhd %hhd",
				&dummy,&ip2[0],&ip2[1],&ip2[2],&ip2[3],&prefix,&dstport,&port))
			{
				fill_ipv4_udp_table(ip2,prefix,dstport,port);
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
	set_default_action_ipv4_tcp();
	set_default_action_ipv4_udp();
    
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
	// else {
    //     // fp = fopen("/home/it-34/t4/t4p4s/ipv6_log.txt","a");
    //     // if(fp){
    //     //         fprintf(fp,"notify____00");
    //     //         fprintf(fp,"\n");
    //     //         fclose(fp);
    //     //     }
	// 	// c = create_controller_with_init(11111, 3, dhf, init_simple);
	// }
    // fp = fopen("/home/it-34/t4/t4p4s/1_log.txt","a");
    //     if(fp){
    //             fprintf(fp,"notify____11");
    //             fprintf(fp,"\n");
    //             fclose(fp);
    //         }
    notify_controller_initialized();

	execute_controller(c);

	destroy_controller(c);

	return 0;
}
