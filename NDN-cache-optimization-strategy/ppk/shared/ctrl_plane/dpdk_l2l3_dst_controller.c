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

void fill_ipv4_lpm_table(uint8_t ip[4],uint8_t prefix,uint8_t dstmac[6],uint8_t port)
{
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap2;
    struct p4_field_match_lpm* lpm;
    struct p4_field_match_exact* exact ,* exact1;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "MyIngress.ipv4_lpm_0");

     FILE *fp6;
     /*fp6 = fopen("/home/zhaoxing/log/ipv4_mul.txt","a");
         if(fp6){
	 	 fprintf(fp6,"ipv4:{%d}:{%d}:{%d}:{%d}",ip[0],ip[1],ip[2],ip[3]);
         fprintf(fp6,"mac:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
                 fprintf(fp6,"\n");
                 fclose(fp6);
             }*/

    exact1 = add_p4_field_match_lpm(te, 2048);
    strcpy(exact1->header.name, "ipv4.dstAddr");
    memcpy(exact1->bitmap, ip, 4);
    exact1->length = 8*4+0;

    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"ethernet.dstAddr");
    memcpy(exact->bitmap,dstmac,6);
    exact->length = 8*6+0;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "MyIngress.ipv4_forward");

    // ap = add_p4_action_parameter(h,a,2048);
    // strcpy(ap->name,"dstmac");
    // memcpy(ap->bitmap,dstmac,6);
    // ap->length = 6*8+0;

    ap2 = add_p4_action_parameter(h, a, 2048);
    strcpy(ap2->name, "port");
    memcpy(ap2->bitmap, &port, 1);
    // ap2->bitmap = port;
    // ap2->bitmap[1] = 0;
    ap2->length = 1*8+1;

    printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    //netconv_p4_field_match_lpm(lpm);
    netconv_p4_field_match_exact(exact);
    netconv_p4_field_match_exact(exact1);
    netconv_p4_action(a);
    // netconv_p4_action_parameter(ap);
    netconv_p4_action_parameter(ap2);
    
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
    uint8_t dstmac[6];
	char dummy;
    // FILE *fp3;
	FILE *f;
	f = fopen(filename,"r");
	if (f == NULL) return -1;

	int line_index = 0;
	while (fgets(line,sizeof(line),f)){
		line[strlen(line)-1] = '\0';
		line_index++;
		printf("Sor:%d.",line_index);
		if(line[0] == 'E'){
			if (13 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhd",
				&dummy,&ip[0],&ip[1],&ip[2],&ip[3],&prefix,&dstmac[0],&dstmac[1],&dstmac[2],&dstmac[3],&dstmac[4],&dstmac[5],&port))
			{
				// fp3 = fopen("/home/zhaoxing/log/l3dst_ipv4_log.txt","a");
                // 		if(fp3){
				//      fprintf(fp3,"ipv4:{%d}{%d}{%d}{%d},{%d}{%d}{%d}{%d}{%d}{%d}",ip[0],ip[1],ip[2],ip[3],dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
                //      		fprintf(fp3,"\n");
                //      		fclose(fp3);
                //  }
				fill_ipv4_lpm_table(ip,prefix,dstmac,port);
                // fp3 = fopen("/home/zhaoxing/log/l3dst_ipv4_log.txt","a");
                // 		if(fp3){
				//      fprintf(fp3,"11111111");
                //      		fprintf(fp3,"\n");
                //      		fclose(fp3);
                //  }
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
	// 	// c = create_controller_with_init(11111, 3, dhf, init_simple);
	// }

    notify_controller_initialized();

	execute_controller(c);

	destroy_controller(c);

	return 0;
}
