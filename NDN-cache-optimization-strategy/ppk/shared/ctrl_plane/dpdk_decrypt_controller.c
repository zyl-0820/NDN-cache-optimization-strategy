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
    strcpy(te->table_name, "MyIngress.ipv4_exact_0");

     FILE *fp6;
    lpm = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm->header.name, "ipv4.dstAddr");
    memcpy(lpm->bitmap, ip, 4);
    lpm->prefix_length = prefix;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "MyIngress.ipv4_forward");

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

void fill_ipv4_spd_table(uint8_t ip[4],uint8_t prefix,uint8_t ip2[4],uint8_t prefix2)
{
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_field_match_lpm* lpm,*lpm2;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "MyIngress.ipv4_spd_0");

     /*FILE *fp6;
     fp6 = fopen("/home/it-34/log/ipv4_mul.txt","a");
         if(fp6){
	 	 fprintf(fp6,"ipv4:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",ip[0],ip[1],ip[2],ip[3],ip[4],ip[5],ip[6],ip[7]);
                 fprintf(fp6,"\n");
                 fclose(fp6);
             }*/

    lpm = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm->header.name, "ipv4.dstAddr");
    memcpy(lpm->bitmap, ip, 4);
    lpm->prefix_length = prefix;

    lpm2 = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm2->header.name, "ipv4.srcAddr");
    memcpy(lpm2->bitmap, ip2, 4);
    lpm2->prefix_length = prefix2;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "MyIngress.ipv4_de_encry");


    printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_lpm(lpm);
    netconv_p4_field_match_lpm(lpm2);
    netconv_p4_action(a);
    
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}

void fill_geo_ternary_table(uint8_t ip2[4],uint8_t mask[4],uint8_t dstmac[6],uint8_t port)
{
    char buffer[2048]; /* TODO: ugly */
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap,*ap2;
    struct p4_field_match_ternary* ternary;

    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "MyIngress.geo_ternary_0");
    
    ternary = add_p4_field_match_ternary(te, 2048);
    strcpy(ternary->header.name, "geo.dstAddr");
    memcpy(ternary->bitmap, ip2, 4);
    memcpy(ternary->mask, mask, 4);
    //ternary->mask = mask;
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
    strcpy(te->table_name, "MyEgress.ipv4_exact_1");

    //  FILE *fp6;
    //  fp6 = fopen("/home/zhaoxing/log/l3dst_ip_log.txt","a");
    //      if(fp6){
	//  	 fprintf(fp6,"ipv4:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",ip[0],ip[1],ip[2],ip[3],ip[4],ip[5],ip[6],ip[7]);
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
    strcpy(a->description.name, "MyEgress.ipv4_ipsec");

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
    memcpy(ap3->bitmap,dAddress, 4);
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

void init_simple() {
	uint8_t ip[4] = {10,0,99,99};
	uint8_t ip2[4] = {10,0,98,98};
	uint8_t ipv6[8] = {};
    uint8_t mask[4] = {255,255,255,255};
    uint8_t dstmac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
	uint8_t port = 1;
    // uint8_t ttl = 0;
    // uint8_t hoplimit = 0;

	fill_ipv4_lpm_table(ip, 24, dstmac,port);
	fill_geo_ternary_table(ip2,mask,dstmac,port);

}
void dhf(void* b) {
       printf("Unknown digest received\n");
}

int read_config_from_file(char *filename)
{
	char line[100];
	uint8_t ip[4];
    uint8_t ip2[4];
	uint8_t ipv6[8];
    uint8_t spi[4];
    uint8_t sAdrress[4];
    uint8_t dAddress[4];
    // int n = -1;
	uint8_t port;
    uint8_t prefix;
    uint8_t prefix2;
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
		if(line[0] == 'E'){
			if (13 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhd",
				&dummy,&ip[0],&ip[1],&ip[2],&ip[3],&prefix,&dstmac[0],&dstmac[1],&dstmac[2],&dstmac[3],&dstmac[4],&dstmac[5],&port))
			{
				//fp3 = fopen("/home/it-34/log/ipv4_log.txt","a");
                		/*if(fp3){
				     fprintf(fp3,"ipv4:{%d}{%d}{%d}{%d},{%d}{%d}{%d}{%d}{%d}{%d}",ip[0],ip[1],ip[2],ip[3],dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
                     		fprintf(fp3,"\n");
                     		fclose(fp3);
                 }*/
				fill_ipv4_lpm_table(ip,prefix,dstmac,port);
			}
			else{
                fclose(f);
                return -1;
			}
		}
		else if (line[0] == 'G'){
			if (16 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd.%hhd.%hhd.%hhd %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %hhd",
				&dummy,&ip2[0],&ip2[1],&ip2[2],&ip2[3],&mask[0],&mask[1],&mask[2],&mask[3],&dstmac[0],&dstmac[1],&dstmac[2],&dstmac[3],&dstmac[4],&dstmac[5],&port))
			{
                 fp3 = fopen("/home/zhaoxin/log/geo_log.txt","a");
                 if(fp3){
				     fprintf(fp3,"geo:{%d}{%d}{%d}{%d},{%d}{%d}{%d}{%d},{%d}{%d}{%d}{%d}{%d}{%d}",ip2[0],ip2[1],ip2[2],ip2[3],mask[0],mask[1],mask[2],mask[3],dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
                     fprintf(fp3,"\n");
                     fclose(fp3);
                 }
				fill_geo_ternary_table(ip2,mask,dstmac,port);
			}
			else{
                fclose(f);
                return -1;
			}
		}
 
        else if(line[0] == 'D'){
			if (11 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd %hhd.%hhd.%hhd.%hhd %hhd",
				&dummy,&ip[0],&ip[1],&ip[2],&ip[3],&prefix,&ip2[0],&ip2[1],&ip2[2],&ip2[3],&prefix2))
			{
				fp3 = fopen("/home/zhaoxin/log/l3dst_ipv4_log.txt","a");
                		if(fp3){
				     fprintf(fp3,"ipv4:{%d}{%d}{%d}{%x},{%d}{%d}{%d}{%d}{%d}{%d}",ip[0],ip[1],ip[2],ip[3],dstmac[0],dstmac[1],dstmac[2],dstmac[3],dstmac[4],dstmac[5]);
                     		fprintf(fp3,"\n");
                     		fclose(fp3);
                 }
				fill_ipv4_spd_table(ip,prefix,ip2,prefix2);
                fp3 = fopen("/home/zhaoxin/log/l3dst_ip_log.txt","a");
                		if(fp3){
				     fprintf(fp3,"****************");
                     		fprintf(fp3,"\n");
                     		fclose(fp3);
                 }
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
	set_default_action_ipv4_lpm();
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
        // fp = fopen("/home/it-34/t4/t4p4s/ipv6_log.txt","a");
        // if(fp){
        //         fprintf(fp,"notify____00");
        //         fprintf(fp,"\n");
        //         fclose(fp);
        //     }
		c = create_controller_with_init(11111, 3, dhf, init_simple);
	}
    // fp = fopen("/home/it-34/t4/t4p4s/1_log.txt","a");
    //     if(fp){
    //             fprintf(fp,"notify____11");
    //             fprintf(fp,"\n");
    //             fclose(fp);
    //         }
    notify_controller_initialized();
    // fp = fopen("/home/it-34/t4/t4p4s/1_log.txt","a");
    //     if(fp){
    //             fprintf(fp,"notify____22");
    //             fprintf(fp,"\n");
    //             fclose(fp);
    //         }

    // fp = fopen("/home/it-34/t4/t4p4s/1_log.txt","a");
    //     if(fp){
    //             fprintf(fp,"notify____33");
    //             fprintf(fp,"\n");
    //             fclose(fp);
    //         }
	execute_controller(c);
    // fp = fopen("/home/it-34/t4/t4p4s/1_log.txt","a");
    //     if(fp){
    //             fprintf(fp,"notify____44");
    //             fprintf(fp,"\n");
    //             fclose(fp);
    //         }

	destroy_controller(c);
    // fp = fopen("/home/it-34/t4/t4p4s/1_log.txt","a");
    //     if(fp){
    //             fprintf(fp,"notify____66");
    //             fprintf(fp,"\n");
    //             fclose(fp);
    //         }

	return 0;
}
