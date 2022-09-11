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
    struct p4_action_parameter* ap,*ap2;
    struct p4_field_match_lpm* lpm;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ipv4_lpm_0");

    //  FILE *fp6;
    //  fp6 = fopen("/home/zhaoxin/log/l3dst_ip_log.txt","a");
    //      if(fp6){
	//  	 fprintf(fp6,"ipv4:{%d}:{%d}:{%d}:{%d}",ip[0],ip[1],ip[2],ip[3]);
    //              fprintf(fp6,"\n");
    //              fclose(fp6);
    //          }

    lpm = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm->header.name, "ipv4.dstAddr");
    memcpy(lpm->bitmap, ip, 4);
    lpm->prefix_length = prefix;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "ipv4_forward");

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

    printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_lpm(lpm);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
    netconv_p4_action_parameter(ap2);
    
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}


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
    strcpy(te->table_name, "dest_guid_exact_0");

    //  FILE *fp6;
    //  fp6 = fopen("/home/it-34/log/l3dst_ip_log.txt","a");
    //      if(fp6){
	//  	 fprintf(fp6,"ipv4:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",nxtHopMac[0],nxtHopMac[1],nxtHopMac[2],nxtHopMac[3],nxtHopMac[4],nxtHopMac[5]);
    //              fprintf(fp6,"\n");
    //              fclose(fp6);
    //          }

    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "mf.dest_guid");
    memcpy(exact->bitmap, dest_guid, 4);
    exact->length = 4*8+0;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "dest_guid_forward");

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


void fill_ipv4_spi_table(uint8_t ip[4],uint8_t prefix,uint8_t spi[4],uint8_t sAdrress[4],uint8_t dAddress[4])
{
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap,*ap2,*ap3;
    struct p4_field_match_lpm* lpm,*lpm1;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ipv4_spi_0");

    //  FILE *fp6;
    //  fp6 = fopen("/home/zhaoxin/log/l3dst_ip_log.txt","a");
    //      if(fp6){
	//  	 fprintf(fp6,"ipv4:{%d}:{%d}:{%d}:{%d}",ip[0],ip[1],ip[2],ip[3]);
    //              fprintf(fp6,"\n");
    //              fclose(fp6);
    //          }

    lpm = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm->header.name, "ipv4.dstAddr");
    memcpy(lpm->bitmap, ip, 4);
    lpm->prefix_length = prefix;

    lpm1 = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm1->header.name, "ipv4.srcAddr");
    memcpy(lpm1->bitmap, ip, 4);
    lpm1->prefix_length = prefix;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "ipv4_ipsec");

    ap = add_p4_action_parameter(h,a,2048);
    strcpy(ap->name,"spi");
    memcpy(ap->bitmap,spi,4);
    ap->length = 4*8+0;

    ap2 = add_p4_action_parameter(h, a, 2048);
    strcpy(ap2->name, "sAdrress");
    memcpy(ap2->bitmap,sAdrress, 4);
    // ap2->bitmap = port;
    // ap2->bitmap[1] = 0;
    ap2->length = 4*8+0;

    ap3 = add_p4_action_parameter(h, a, 2048);
    strcpy(ap3->name, "dAddress");
    memcpy(ap3->bitmap,sAddress, 4);
    ap3->length = 4*8+0;

    printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_lpm(lpm);
    netconv_p4_field_match_lpm(lpm1);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
    netconv_p4_action_parameter(ap2);
    netconv_p4_action_parameter(ap3);
    
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}


void fill_ipv4_spd_table(uint8_t ip[4],uint8_t prefix)
{
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    // struct p4_action_parameter* ap,*ap2,*ap3;
    struct p4_field_match_lpm* lpm,*lpm1;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ipv4_spd_0");

    //  FILE *fp6;
    //  fp6 = fopen("/home/zhaoxin/log/l3dst_ip_log.txt","a");
    //      if(fp6){
	//  	 fprintf(fp6,"ipv4:{%d}:{%d}:{%d}:{%d}",ip[0],ip[1],ip[2],ip[3]);
    //              fprintf(fp6,"\n");
    //              fclose(fp6);
    //          }

    lpm = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm->header.name, "ipv4.dstAddr");
    memcpy(lpm->bitmap, ip, 4);
    lpm->prefix_length = prefix;

    lpm1 = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm1->header.name, "ipv4.srcAddr");
    memcpy(lpm1->bitmap, ip, 4);
    lpm1->prefix_length = prefix;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "ipv4_de_encry");

    // ap = add_p4_action_parameter(h,a,2048);
    // strcpy(ap->name,"spi");
    // memcpy(ap->bitmap,spi,4);
    // ap->length = 4*8+0;

    // ap2 = add_p4_action_parameter(h, a, 2048);
    // strcpy(ap2->name, "sAdrress");
    // memcpy(ap2->bitmap,sAdrress, 4);
    // // ap2->bitmap = port;
    // // ap2->bitmap[1] = 0;
    // ap2->length = 4*8+0;

    // ap3 = add_p4_action_parameter(h, a, 2048);
    // strcpy(ap3->name, "sAdrress");
    // memcpy(ap3->bitmap,dAddress, 4);
    // ap3->length = 4*8+0;

    printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_lpm(lpm);
    netconv_p4_field_match_lpm(lpm1);
    netconv_p4_action(a);
    // netconv_p4_action_parameter(ap);
    // netconv_p4_action_parameter(ap2);
    // netconv_p4_action_parameter(ap3);
    
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}


void fill_dest_guid_spi_table(uint8_t dest_guid[4],uint8_t spi[4],uint8_t sAdrress[4],uint8_t dAddress[4])
{
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap,*ap2,* ap3;
    struct p4_field_match_exact* exact;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "dest_guid_spi_0");


    exact = add_p4_field_match_exact(te, 2048);
    strcpy(exact->header.name, "mf.dest_guid");
    memcpy(exact->bitmap, dest_guid, 4);
    exact->length = 4*8+0;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "mf_ipsec");

    ap = add_p4_action_parameter(h,a,2048);
    strcpy(ap->name,"spi");
    memcpy(ap->bitmap,spi,4);
    ap->length = 4*8+0;

    ap2 = add_p4_action_parameter(h, a, 2048);
    strcpy(ap2->name, "sAdrress");
    memcpy(ap2->bitmap, sAdrress, 4);
    ap2->length = 4*8+0;

    ap3 = add_p4_action_parameter(h, a, 2048);
    strcpy(ap3->name, "dAddress");
    memcpy(ap3->bitmap, dAddress, 4);
    ap3->length = 4*8+0;

    printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
    netconv_p4_action_parameter(ap2);
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
	uint8_t ip[4];
    uint8_t dest_guid[4];
    // int n = -1;
	uint8_t port;
    uint8_t spi[4];
    uint8_t sAdrress[4];
    uint8_t dAddress[4];
    uint8_t prefix;
    uint8_t dstmac[6];
    uint8_t nxtHopMac[6];
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
		if(line[0] == 'A'){
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

			}
			else{
                fclose(f);
                return -1;
			}
		}

        else if(line[0] == 'B'){
			if (12 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhd",
				&dummy,&dest_guid[0],&dest_guid[1],&dest_guid[2],&dest_guid[3],&nxtHopMac[0],&nxtHopMac[1],&nxtHopMac[2],&nxtHopMac[3],&nxtHopMac[4],&nxtHopMac[5],&port))
			{
				// fp3 = fopen("/home/zhaoxing/log/l3dst_ipv4_log.txt","a");
                // 		if(fp3){
				//      fprintf(fp3,"ipv4:{%d}{%d}{%d}{%d},{%d}{%d}{%d}{%d}{%d}{%d}",ip[0],ip[1],ip[2],ip[3],dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
                //      		fprintf(fp3,"\n");
                //      		fclose(fp3);
                //  }
				fill_dest_guid_exact_table(dest_guid,nxtHopMac,port);

			}
			else{
                fclose(f);
                return -1;
			}
		}

        else if(line[0] == 'C'){
			if (18 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx",
				&dummy,&ip[0],&ip[1],&ip[2],&ip[3],&prefix,&spi[0],&spi[1],&spi[2],&spi[3],&sAdrress[0],&sAdrress[1],&sAdrress[2],&sAdrress[3],&dAddress[0],&dAddress[1],&dAddress[2],&dAddress[3]))
			{
				// fp3 = fopen("/home/zhaoxing/log/l3dst_ipv4_log.txt","a");
                // 		if(fp3){
				//      fprintf(fp3,"ipv4:{%d}{%d}{%d}{%d},{%d}{%d}{%d}{%d}{%d}{%d}",ip[0],ip[1],ip[2],ip[3],dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
                //      		fprintf(fp3,"\n");
                //      		fclose(fp3);
                //  }
				fill_ipv4_spi_table(ip,prefix,spi,sAdrress,dAddress);

			}
			else{
                fclose(f);
                return -1;
			}
		}

        else if(line[0] == 'D'){
			if (6 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd",
				&dummy,&ip[0],&ip[1],&ip[2],&ip[3],&prefix))
			{
				// fp3 = fopen("/home/zhaoxing/log/l3dst_ipv4_log.txt","a");
                // 		if(fp3){
				//      fprintf(fp3,"ipv4:{%d}{%d}{%d}{%d},{%d}{%d}{%d}{%d}{%d}{%d}",ip[0],ip[1],ip[2],ip[3],dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
                //      		fprintf(fp3,"\n");
                //      		fclose(fp3);
                //  }
				fill_ipv4_spd_table(ip,prefix);

			}
			else{
                fclose(f);
                return -1;
			}
		}

        else if(line[0] == 'E'){
			if (17 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx",
				&dummy,&dest_guid[0],&dest_guid[1],&dest_guid[2],&dest_guid[3],&spi[0],&spi[1],&spi[2],&spi[3],&sAdrress[0],&sAdrress[1],&sAdrress[2],&sAdrress[3],&dAddress[0],&dAddress[1],&dAddress[2],&dAddress[3]))
			{
				// fp3 = fopen("/home/zhaoxing/log/l3dst_ipv4_log.txt","a");
                // 		if(fp3){
				//      fprintf(fp3,"ipv4:{%d}{%d}{%d}{%d},{%d}{%d}{%d}{%d}{%d}{%d}",ip[0],ip[1],ip[2],ip[3],dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
                //      		fprintf(fp3,"\n");
                //      		fclose(fp3);
                //  }
				fill_dest_guid_spi_table(dest_guid,spi,sAdrress,dAddress);

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
	// set_default_action_ipv4_lpm();

	if (read_config_from_file(fn)<0) {
        // fp3 = fopen("/home/zhaoxing/log/l3dst_ip_log.txt","a");
        //         		if(fp3){
		// 		     fprintf(fp3,"<<<<<<<<read_config_from_file(fn)<0");
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