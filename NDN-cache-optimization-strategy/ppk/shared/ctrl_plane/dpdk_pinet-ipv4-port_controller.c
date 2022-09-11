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
FILE *fp;

controller c;

void fill_ipv4_lpm_table(uint8_t ins_port,uint8_t port)
{
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    struct p4_field_match_exact* exact;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ipv4_lpm_0");


    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"standard_metadata.ingress_port");
    memcpy(exact->bitmap,&ins_port,1);
    exact->length = 8*1+1;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "ipv4_forward");

    ap = add_p4_action_parameter(h, a, 2048);
    strcpy(ap->name, "port");
    memcpy(ap->bitmap, &port, 1);
    // ap->bitmap = port;
    // ap->bitmap[1] = 0;
    ap->length = 8*1+1;

    //printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
    
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}




void dhf(void* b) {
       //printf("Unknown digest received\n");
}


int read_config_from_file(char *filename)
{
	char line[100];
    // int n = -1;
	uint8_t port;
    uint8_t ins_port;
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
			if (3 == sscanf(line,"%c %hhd %hhd",
				&dummy,&ins_port,&port))
			{
				fill_ipv4_lpm_table(ins_port,port);
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
