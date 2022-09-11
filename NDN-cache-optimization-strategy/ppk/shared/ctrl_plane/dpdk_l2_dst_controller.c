#include "controller.h"
#include "messages.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_MACS 60000

controller c;
FILE* fp3;

extern void notify_controller_initialized();

void fill_ether_exact_table(uint8_t mac[6],uint8_t port){
    char buffer[2048];
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    // struct p4_field_match_header* fmh;
    struct p4_field_match_exact* exact;
         
    // fp3 = fopen("/home/zhaoxing/log/fill_l2_dst.txt","a");
    //     if(fp3){
    //     fprintf(fp3,"mac:{%d}{%d}{%d}{%d}{%d}{%d}",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    //     fprintf(fp3,"\n");
    //     fclose(fp3);
    //  }


    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ingress.ether_exact_0");

    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "ethernet.dstAddr");
    memcpy(exact->bitmap, mac, 6);
    exact->length = 6*8+0;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "ingress.l2_forword");

    ap = add_p4_action_parameter(h, a, 2048);	
    strcpy(ap->name, "port");
    memcpy(ap->bitmap, &port, 1);
    ap->length = 1*8+1;

    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);

    send_p4_msg(c,buffer,2048);
}


void set_default_action_ether_exact()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;

    //printf("Generate set_default_action message for table ether_exact\n");

    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "ether_exact_0");

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


int read_config_from_file(char *filename) {
    FILE *f;
    char line[100];
    uint8_t mac[6];
    uint8_t port;
    char dummy;

    f = fopen(filename, "r");
    if (f == NULL) return -1;

    int line_index = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strlen(line)-1] = '\0';
        line_index++;
        //printf("Sor: %d.",line_index);
        if (line[0]=='M') {
            if (8 == sscanf(line, "%c %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhd",
                            &dummy, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5] ,&port))
            {
                fill_ether_exact_table(mac,port);
            }

            
            else {
                //printf("Wrong format error in line\n");
                fclose(f);
                return -1;
            }
        }

    }
    fclose(f);
    return 0;
}

char* fn;
void init_complex() {
    set_default_action_ether_exact();
    
    if (read_config_from_file(fn)<0) {

         //printf("File cannnot be opened...\n");
    }
}


int main(int argc, char* argv[])
{
	//printf("Create and configure controller...xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxmmmmmmmm\n");

	if (argc>1) {
		if (argc!=2) {
			//printf("Too many arguments...\nUsage: %s <filename(optional)>\n", argv[0]);
			return -1;
		}

		//printf("Command line argument is present...\nLoading configuration data...\n");
       	fn = argv[1];

		c = create_controller_with_init(11111, 3, dhf, init_complex);
   }

    notify_controller_initialized();


	//printf("Launching controller's main loop...\n");
	execute_controller(c);


	//printf("Destroy controller\n");
	destroy_controller(c);


	return 0;
}

