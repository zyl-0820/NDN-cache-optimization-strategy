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

void fill_ipv4_lpm_table(uint8_t ip[4],uint8_t prefix,uint8_t port)
{
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    struct p4_field_match_lpm* lpm;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ingress.ipv4_lpm_0");


     fp3 = fopen("/home/zhaoxin/log/l3dst_ip_log.txt","a");
         if(fp3){
	 	 fprintf(fp3,"ipv4:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",ip[0],ip[1],ip[2],ip[3],ip[4],ip[5],ip[6],ip[7]);
                 fprintf(fp3,"\n");
                 fclose(fp3);
             }

    lpm = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm->header.name, "ipv4.dstAddr");
    memcpy(lpm->bitmap, ip, 4);
    lpm->prefix_length = prefix;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "ingress.ipv4_static");


    // ap2 = add_p4_action_parameter(h, a, 2048);
    // strcpy(ap2->name, "port");
    // memcpy(ap2->bitmap, &port, 4);
    // // ap2->bitmap = port;
    // // ap2->bitmap[1] = 0;
    // ap2->length = 4*8+0;

    printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_lpm(lpm);
    netconv_p4_action(a);
    // netconv_p4_action_parameter(ap);
    // netconv_p4_action_parameter(ap2);
    
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}
void fill_stateful_forward_table(uint8_t mod_result,uint8_t port){
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    struct p4_field_match_exact* exact;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ingress.stateful_forward_0");

    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"mod_result");
    memcpy(exact->bitmap,&mod_result,1);
    exact->length = 8*1+0;

    a = add_p4_action(h,2048);
    strcpy(a->description.name,"ingress.forward");
    
    ap = add_p4_action_parameter(h, a, 2048);
    strcpy(ap->name, "port");
    memcpy(ap->bitmap, &port, 1);
        
    // // ap->bitmap = port;
    // // ap->bitmap[1] = 0;
    ap->length = 8*1+1;

    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}

void set_default_action_ipv4_lpm()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;


    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "ipv4_lpm_0");

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


int read_config_from_file(char *filename)
{
	char line[100];
	uint8_t ip[4];
    // int n = -1;
	uint8_t port;
    uint8_t prefix;
    uint8_t mod_result;
	char dummy;
    FILE *fp3;
	FILE *f;
	f = fopen(filename,"r");
	if (f == NULL) return -1;

	int line_index = 0;
	while (fgets(line,sizeof(line),f)){
		line[strlen(line)-1] = '\0';
		line_index++;
		printf("Sor:%d.",line_index);
		if(line[0] == 'E'){
                 fp3 = fopen("/home/zhaoxin/log/l3dst_ip_log.txt","a");
         if(fp3){
	 	 fprintf(fp3,"ipv4:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",ip[0],ip[1],ip[2],ip[3],ip[4],ip[5],ip[6],ip[7]);
                 fprintf(fp3,"\n");
                 fclose(fp3);
             }
			if (7 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd %hhd",
				&dummy,&ip[0],&ip[1],&ip[2],&ip[3],&prefix,&port))
			{
				fill_ipv4_lpm_table(ip,prefix,port);
			}
			else{
                fclose(f);
                return -1;
			}
		}else if(line[0]== 'F'){
            if(3 == sscanf(line,"%c %hhd %hhd",&dummy,&mod_result,&port)){
                fill_stateful_forward_table(mod_result,port);
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
	set_default_action_ipv4_lpm();

	if (read_config_from_file(fn)<0) {
        // fp3 = fopen("/home/zhaoxing/log/l3dst_ip_log.txt","a");
        //         		if(fp3){
		// 		     fprintf(fp3,"<<<<<<<<<<00000000>>>>>>>>>>");
        //              		fprintf(fp3,"\n");
        //              		fclose(fp3);
        //          }
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
    notify_controller_initialized();

	execute_controller(c);

	destroy_controller(c);

	return 0;
}
