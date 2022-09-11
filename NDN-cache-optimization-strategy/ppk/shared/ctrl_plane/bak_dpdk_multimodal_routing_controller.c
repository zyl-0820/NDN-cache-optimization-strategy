#include "controller.h"
#include "messages.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_IPS 60000



// typedef char Ipv6[4];
extern int usleep(__useconds_t usec);
extern void notify_controller_initialized();

controller c;
void fill_ipv4_lpm_table(uint8_t ip[4],uint8_t prefix,uint8_t dmac[6],uint8_t port)
//void fill_ipv4_lpm_table(uint8_t ip[4],uint8_t prefix,uint8_t port,uint8_t ttl)
{
    FILE *fp2;
    fp2 = fopen("/home/it-34/log/f_ipv4_log.txt","a+");
    if(fp2){
        fprintf(fp2,"in fill_ipv4_lpm_table\n");
        fprintf(fp2,"\n");
                // fprintf(fp2," 02x: %d :%02x%02x%02x%02x%02x%02x\n",n, m[0], m[1],m[2],m[3], m[4], m[5]);
        }
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
   // struct p4_action_parameter* ap;
    struct p4_action_parameter* ap,*ap0;
    struct p4_field_match_lpm* lpm;
    printf("ipv4_lpm\n");
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ipv4_lpm_0");

    lpm = add_p4_field_match_lpm(te, 2048);
    strcpy(lpm->header.name, "ipv4.dstAddr");
    memcpy(lpm->bitmap, ip, 4);
    lpm->prefix_length = prefix;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "ipv4_forward");

    printf("dmac\n");
    ap0 = add_p4_action_parameter(h, a, 2048);   
    strcpy(ap0->name, "dmac");
    memcpy(ap0->bitmap, dmac,6);
    //ap->bitmap[0] = port;
    //ap->bitmap[1] = 0;
    ap0->length = 6*8+0;

    printf("port\n");
    ap = add_p4_action_parameter(h, a, 2048);	
    strcpy(ap->name, "port");
    memcpy(ap->bitmap, &port,4);
    //ap->bitmap[0] = port;
    //ap->bitmap[1] = 0;
    ap->length = 4*8+0;
/*
    ap2 = add_p4_action_parameter(h, a, 2048);	
    strcpy(ap2->name, "ttl");
    memcpy(ap2->bitmap, &ttl, 4);
    ap2->length = 4*8+0;
*/
    printf("NH-1\n");
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_lpm(lpm);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
//    netconv_p4_action_parameter(ap2);
    
    send_p4_msg(c, buffer, 2048);
    fprintf(fp2,"end fill_ipv4_lpm_table1111\n");
    fclose(fp2);
    usleep(1200);
}


void fill_geo_ternary_table(uint8_t ip2[4],uint8_t prefix,uint8_t port,uint8_t ttl)
{
                // n = sscanf("010203040506", "%02x%02x%02x%02x%02x%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
    char buffer[2048]; /* TODO: ugly */
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap,*ap2;
    struct p4_field_match_ternary* ternary;

	printf("geo_ternary\n");
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "geo_ternary_0");

    ternary = add_p4_field_match_ternary(te, 2048);
    strcpy(ternary->header.name, "geo.dstAddr");
    memcpy(ternary->bitmap, ip2, 4);
    ternary->length = 4*8+0;

    a = add_p4_action(h, 2048);
    strcpy(a->description.name, "geo_forward");

    ap = add_p4_action_parameter(h, a, 2048);	
    strcpy(ap->name, "port");
    memcpy(ap->bitmap, &port, 4);
    ap->length = 4*8+0;

    ap2 = add_p4_action_parameter(h,a,2048);
    strcpy(ap2->name,"ttl");
    memcpy(ap2->bitmap,&ttl,4);
    ap2->length = 4*8+0;

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

//void fill_ipv6_exact_table(uint8_t ipv6[8],uint8_t port,uint8_t hopLimit)
void fill_ipv6_exact_table(uint8_t ipv6[8],uint8_t port)
{
    char buffer[2048]; /* TODO: ugly */
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
     //struct p4_action_parameter* ap,*ap2;   
    struct p4_field_match_exact* exact;
    FILE *fp6;
    fp6 = fopen("/home/it-34/log/ipv6_log2.txt","a");
        if(fp6){
				fprintf(fp6,"ipv6:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",ipv6[0],ipv6[1],ipv6[2],ipv6[3],ipv6[4],ipv6[5],ipv6[6],ipv6[7]);
                fprintf(fp6,"\n");
                fclose(fp6);
            }
    printf("ipv6_exact_table\n");

    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048); 
    strcpy(te->table_name, "ipv6_exact_0");

    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"ipv6.dstAddr");
    memcpy(exact->bitmap,ipv6,16);
    exact->length = 8*16+0;

    a = add_p4_action(h,2048);
    strcpy(a->description.name,"ipv6_forward");

    // ap = add_p4_action_parameter(h,a,2048);
    // strcpy(ap->name,"dstAddr");
    // memcpy(ap->bitmap, dstAddr, 6);
    // ap->length = 6*8+0;
    ap = add_p4_action_parameter(h,a,2048);
    strcpy(ap->name, "port");
    memcpy(ap->bitmap,&port,4);
    ap->bitmap[0] = port;
    ap->length = 4*8+0;

/*
    ap2 = add_p4_action_parameter(h,a,2048);
    strcpy(ap2->name,"hopLimit");
    memcpy(ap2->bitmap, &hopLimit, 4);
    ap2->length = 4*8+0;
*/
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
//    netconv_p4_action_parameter(ap2);
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}

void set_default_action_ipv4_lpm()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;

    printf("Generate set_default_action message for table ipv4_lpm\n");

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

    printf("Generate set_default_action message for table geo_ternary\n");

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

void set_default_action_ipv6_exact()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;

    printf("Generate set_default_action message for table ipv6_exact\n");

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
	uint8_t ip[4] = {10,0,99,99};
	uint8_t ip2[4] = {10,0,98,98};
	uint8_t ipv6[8] = {};
    uint8_t dmac[6] ={11,22,33,44,55,66};
	uint8_t port = 1;
    uint8_t ttl = 0;
    uint8_t hoplimit = 0;

//	fill_ipv4_lpm_table(ip, 16, port,ttl);
    fill_ipv4_lpm_table(ip, 16, dmac,port);
	fill_geo_ternary_table(ip2,16,port,ttl);
	fill_ipv6_exact_table(ipv6,port);
//fill_ipv6_exact_table(ipv6,port,hoplimit);
}

FILE *Frcff;

int read_config_from_file(char *filename)
{
    FILE  *f;
	char line[200];
	uint8_t ip[4];
    uint8_t dmac[6];
    uint8_t ip2[4];
	uint8_t ipv6[8];
	uint8_t port;
	uint8_t prefix;
    uint8_t ttl;
    uint8_t hoplimit;
	char dummy;
    Frcff = fopen("/home/it-34/log/read_and_config_form_file_log.txt","a+");
    fprintf(Frcff,"xixihaha1\n");
	f = fopen(filename,"r");
	if (f == NULL) 
    {
        fprintf(Frcff,"Table open failed\n");
        fclose(Frcff);
        return -1;
    }
    else
    {
       fprintf(Frcff,"Table open Sucess\n");
       fclose(Frcff);

    }
	int line_index = 0;
	while (fgets(line,sizeof(line),f))
    {
		line[strlen(line)-1] = '\0';
		line_index++;
		printf("Sor:%d.",line_index);
		if(line[0] == 'E')
        {
			Frcff = fopen("/home/it-34/log/read_config_form.txt","a+");
			fprintf(Frcff,"0000000000000\n");
			if (13 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd %hhd:%hhd:%hhd:%hhd:%hhd:%hhd %hhd",
				&dummy,&ip[0],&ip[1],&ip[2],&ip[3],&prefix,&dmac[0],&dmac[1],&dmac[2],&dmac[3],&dmac[4],&dmac[5],&port))
			{
                //Frcff = fopen("/home/it-34/log/read_config_form.txt","a+");
                // n = sscanf("010203040506", "%02x%02x%02x%02x%02x%02x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
				fprintf(Frcff,"1111111111111\n");
				fill_ipv4_lpm_table(ip,prefix,dmac,port);
				fprintf(Frcff,"2222222222222\n");
              //fill_ipv4_lpm_table(ip,prefix,port,ttl);
                printf("fill_ipv4");
                fprintf(Frcff,"ipv4_right format\n");
                fprintf(Frcff,"\n\n");
                fclose(Frcff);
			}
			else
            {
				printf("Wrong format error in line\n");
                fclose(f);
                fprintf(Frcff,"ipv4_wrong format\n");
                fprintf(Frcff,"\n\n");
                fclose(Frcff);
                return -1;
			}
		}
		else if (line[0] == 'G')
        {
			if (8 == sscanf(line,"%c %hhd.%hhd.%hhd.%hhd %hhd %hhd %hhd",
				&dummy,&ip2[0],&ip2[1],&ip2[2],&ip2[3],&prefix,&port,&ttl))
			{
                Frcff = fopen("/home/it-34/log/read_and_config_form_file_log.txt","a+");
				fprintf(Frcff,"ipv4:{%s},{%d}",ip2,port);
                fprintf(Frcff,"\n");
				fill_geo_ternary_table(ip2,prefix,port,ttl);
                printf("fill_geo");
                fclose(Frcff);
			}
			else{
                Frcff = fopen("/home/it-34/log/read_and_config_form_file_log.txt","a+");
				printf("Wrong format error in line\n");
                fprintf(Frcff,"geo_wrong format\n");\
                fclose(Frcff);
                fclose(f);
                return -1;
			}
		}
		else if (line[0] == 'S'){
			if(19 == sscanf(line,"%c %2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx:%2hhx%2hhx %hhd %hhd"
                ,&dummy,&ipv6[0],&ipv6[1],&ipv6[2],&ipv6[3],&ipv6[4],&ipv6[5],&ipv6[6],&ipv6[7],&ipv6[8],&ipv6[9],&ipv6[10],&ipv6[11],&ipv6[12],&ipv6[13],&ipv6[14],&ipv6[15],&port,&hoplimit))
			{
                Frcff = fopen("/home/it-34/log/read_and_config_form_file_log.txt","a+");
                fprintf(Frcff,"xixihaha");
				fprintf(Frcff,"ipv6:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}:{%d}",ipv6[0],ipv6[1],ipv6[2],ipv6[3],ipv6[4],ipv6[5],ipv6[6],ipv6[7],ipv6[8],ipv6[9],ipv6[10],ipv6[11],ipv6[12],ipv6[13],ipv6[14],ipv6[15]);
                fprintf(Frcff,"\n");
                fill_ipv6_exact_table(ipv6,port);
                printf("fill_ipv6");
                fclose(Frcff);
            }
			else{
                Frcff = fopen("/home/it-34/log/read_and_config_form_file_log.txt","a+");
				printf("Wrong format error in line\n");
                fprintf(Frcff,"ipv6_wrong format\n");
                fclose(Frcff);               
                fclose(f);
                return -1;
			}
		}
		else{
				printf("Wrong format error in line\n");
                fclose(f);
                return -1;
		}
	}
    Frcff = fopen("/home/it-34/log/read_and_config_form_file_log.txt","a+");
    fprintf(Frcff,"never into the while_loop\n");    
	fclose(f);
	return 0;
}

char* fn;
FILE *fp;
void init_complex(){
	set_default_action_ipv4_lpm();
	set_default_action_geo_ternary();
	set_default_action_ipv6_exact();

    FILE *fp2;
    fp2 = fopen("/home/it-34/log/init_complex.txt","a+");
	if (read_config_from_file(fn)<0) {
        fprintf(fp2, "read faile\n" );
        printf("File cannnot be opened...\n");
    }
    fclose(fp2);
}

int main(int argc, char* argv[])
{
	printf("Create and configure controller...\n");

	if (argc>1) {
		if (argc!=2) {
			printf("Too many arguments...\nUsage: %s <filename(optional)>\n", argv[0]);
			return -1;
		}
		printf("Command line argument is present...\nLoading configuration data...\n");
        fn = argv[1];
		c = create_controller_with_init(11111, 3, dhf, init_complex);
	}
	else {
        fp = fopen("/home/it-34/log/ipv6_log3.txt","a+");
        if(fp){
                fprintf(fp,"notify____00");
                fprintf(fp,"\n");
                fclose(fp);
            }
		c = create_controller_with_init(11111, 3, dhf, init_simple);
	}
    fp = fopen("/home/it-34/log/1_log.txt","w+");
        if(fp){
                fprintf(fp,"notify____1");
                fprintf(fp,"\n");
                fclose(fp);
            }
    notify_controller_initialized();

	printf("Launching controller's main loop...\n");
	execute_controller(c);

	printf("Destroy controller\n");
	destroy_controller(c);
	return 0;
}
