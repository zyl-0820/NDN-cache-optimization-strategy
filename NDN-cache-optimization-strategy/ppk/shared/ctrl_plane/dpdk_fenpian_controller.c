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
FILE *fp6;

controller c;

void fill_section_table_table(uint8_t isvalid){
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    // struct p4_action_parameter* ap,*ap2;
    struct p4_field_match_exact* exact;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ingress.section_table_0");
    
    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"hdr_ndnlpfragcount_flag");
    memcpy(exact->bitmap,&isvalid,1);
    exact->length = 8*1+0;
    
    a = add_p4_action(h,2048);
    strcpy(a->description.name,"ingress.readSection");


    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}


void fill_count_table_table(uint8_t isvalid[5],uint8_t isvalid5){
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    struct p4_field_match_exact* exact,*exact1,*exact2,*exact3,*exact4;
    // struct p4_field_match_exact* exact = (struct p4_field_match_exact*)malloc(sizeof(struct p4_field_match_exact));
    // struct p4_field_match_exact* exact1 = (struct p4_field_match_exact*)malloc(sizeof(struct p4_field_match_exact));
    // struct p4_field_match_exact* exact2 = (struct p4_field_match_exact*)malloc(sizeof(struct p4_field_match_exact));
    // struct p4_field_match_exact* exact3 = (struct p4_field_match_exact*)malloc(sizeof(struct p4_field_match_exact));
    // struct p4_field_match_exact* exact4 = (struct p4_field_match_exact*)malloc(sizeof(struct p4_field_match_exact));


    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ingress.count_table_0");

    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"hdr_component1_flag");
    memcpy(exact->bitmap,&isvalid[0],1);
    exact->length = 8*1+0;

    exact1 = add_p4_field_match_exact(te,2048);
    strcpy(exact1->header.name,"hdr_component2_flag");
    memcpy(exact1->bitmap,&isvalid[1],1);

    exact2 = add_p4_field_match_exact(te,2048);
    strcpy(exact2->header.name,"hdr_component3_flag");
    memcpy(exact2->bitmap,&isvalid[2],1);
    exact2->length = 8*1+0;

    exact3 = add_p4_field_match_exact(te,2048);
    strcpy(exact3->header.name,"hdr_component4_flag");
    memcpy(exact3->bitmap,&isvalid[3],1);
    exact3->length = 8*1+0;

    exact4 = add_p4_field_match_exact(te,2048);
    strcpy(exact4->header.name,"hdr_component5_flag");
    memcpy(exact4->bitmap,&isvalid[4],1);
    exact4->length = 8*1+0;

    a = add_p4_action(h,2048);
    strcpy(a->description.name,"ingress.storeNumOfComponents");

    ap = add_p4_action_parameter(h, a, 2048);
    strcpy(ap->name, "total");
    memcpy(ap->bitmap, &isvalid5, 1);

    // // ap->bitmap = port;
    // // ap->bitmap[1] = 0;
    ap->length = 8*1+0;

    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_field_match_exact(exact1);
    netconv_p4_field_match_exact(exact2);
    netconv_p4_field_match_exact(exact3);
    netconv_p4_field_match_exact(exact4);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}


void fill_fib_table_table(uint8_t isvalid,uint16_t isvalid1[5],uint8_t isvalid2){
    char buffer[4096]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    struct p4_action_parameter* ap;
    struct p4_field_match_exact* exact;
    struct p4_field_match_exact* exact5,*exact1,*exact2,*exact3,*exact4;

    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ingress.fib_table_0");

    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"name_metadata.components");
    memcpy(exact->bitmap,&isvalid,1);
    exact->length = 8*2+0;

     
    exact1 = add_p4_field_match_exact(te, 2048);
    strcpy(exact1->header.name, "comp_metadata.c1");
    memcpy(exact1->bitmap, &isvalid1[0], 2);
    exact1->length = 8*2+0;

    exact2 = add_p4_field_match_exact(te, 2048);
    strcpy(exact2->header.name, "comp_metadata.c2");
    memcpy(exact2->bitmap, &isvalid1[1], 2);
    exact2->length = 8*2+0;

    exact3 = add_p4_field_match_exact(te, 2048);
    strcpy(exact3->header.name, "comp_metadata.c3");
    memcpy(exact3->bitmap, &isvalid1[2], 2);
    exact3->length = 8*2+0;

    exact4 = add_p4_field_match_exact(te, 2048);
    strcpy(exact4->header.name, "comp_metadata.c4");
    memcpy(exact4->bitmap, &isvalid1[3], 2);
    exact4->length = 8*2+0;

    exact5 = add_p4_field_match_exact(te, 2048);

    strcpy(exact5->header.name, "comp_metadata.name_hash");
    memcpy(exact5->bitmap, &isvalid1[4], 2);
    exact5->length = 8*1+0;

    a = add_p4_action(h,2048);
    strcpy(a->description.name,"ingress.set_egr");

    ap = add_p4_action_parameter(h, a, 2048);
    strcpy(ap->name, "egress_spec");
    memcpy(ap->bitmap, &isvalid2, 1);
        
    // // ap->bitmap = port;
    // // ap->bitmap[1] = 0;
    ap->length = 8*1+1;
    fp6 = fopen("/home/zjlab/log/fenpian.txt","a");
         if(fp6){
	 	 fprintf(fp6,"fib_table:{%d},{%d},{%d},{%d},{%d},{%d},{%d}",isvalid,isvalid1[0],isvalid1[1],isvalid1[2],isvalid1[3],isvalid1[4],isvalid2);
                 fprintf(fp6,"\n");
                 fclose(fp6);
             }
    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);

    netconv_p4_field_match_exact(exact1);
    netconv_p4_field_match_exact(exact2);
    netconv_p4_field_match_exact(exact3);
    netconv_p4_field_match_exact(exact4);
    netconv_p4_field_match_exact(exact5);
    netconv_p4_action(a);
    netconv_p4_action_parameter(ap);
    send_p4_msg(c, buffer, 2048);
    usleep(1200);

}


void fill_pit_table_table(char isvalid,uint8_t is_valid){
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a,*a1;
    // struct p4_action_parameter* ap;
    struct p4_field_match_exact* exact;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ingress.pit_table_0");

    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"flow_metadata.packetType");
    memcpy(exact->bitmap,&isvalid,1);
    exact->length = 8*1+0;
    fp6 = fopen("/home/zjlab/log/fenpian.txt","a");
         if(fp6){
	 	 fprintf(fp6,"pit_table:{%d}",is_valid);
                 fprintf(fp6,"\n");
                 fclose(fp6);
             }
    if(is_valid == 0){
        a = add_p4_action(h,2048);
        strcpy(a->description.name,"ingress.readPitEntry");
        netconv_p4_header(h);
        netconv_p4_add_table_entry(te);
        netconv_p4_field_match_exact(exact);
        netconv_p4_action(a);
        send_p4_msg(c, buffer, 2048);
        usleep(1200);
        }
    else if (is_valid  == 1){
            
        a1 = add_p4_action(h,2048);
        strcpy(a1->description.name,"ingress.cleanPitEntry");
        netconv_p4_header(h);
        netconv_p4_add_table_entry(te);
        netconv_p4_field_match_exact(exact);
        netconv_p4_action(a1);
        send_p4_msg(c, buffer, 2048);
        usleep(1200);
        fp6 = fopen("/home/zjlab/log/fenpian.txt","a");
         if(fp6){
	 	 fprintf(fp6,"11111111111111111111");
                 fprintf(fp6,"\n");
                 fclose(fp6);
             }
    }
}


void fill_updatecs_table_table(uint8_t isvalid){
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a,*a1;
    // struct p4_action_parameter* ap;
    struct p4_field_match_exact* exact;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ingress.updatecs_table_0");

    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"hdr_ndnlpfragcount_flag");
    memcpy(exact->bitmap,&isvalid,1);
    exact->length = 8*1+0;
    if(isvalid == 0){
        a1 = add_p4_action(h,2048);
        strcpy(a1->description.name,"ingress.updateCsEntry");
        netconv_p4_header(h);
        netconv_p4_add_table_entry(te);
        netconv_p4_field_match_exact(exact);
        netconv_p4_action(a1);
        send_p4_msg(c, buffer, 2048);
        usleep(1200);
        }
    else if (isvalid  == 1){
        a = add_p4_action(h,2048);
        strcpy(a->description.name,"ingress.addCstoMutist");
        netconv_p4_header(h);
        netconv_p4_add_table_entry(te);
        netconv_p4_field_match_exact(exact);
        netconv_p4_action(a);
        send_p4_msg(c, buffer, 2048);
        usleep(1200);
    }
}


void fill_updatePit_table_table(uint8_t isvalid){
    char buffer[2048]; 
    struct p4_header* h;
    struct p4_add_table_entry* te;
    struct p4_action* a;
    // struct p4_action_parameter* ap;
    struct p4_field_match_exact* exact;
    h = create_p4_header(buffer, 0, 2048);
    te = create_p4_add_table_entry(buffer,0,2048);
    strcpy(te->table_name, "ingress.updatePit_table_0");

    exact = add_p4_field_match_exact(te,2048);
    strcpy(exact->header.name,"flow_metadata.hasFIBentry");
    memcpy(exact->bitmap,&isvalid,1);
    exact->length = 8*1+0;

    a = add_p4_action(h,2048);
    strcpy(a->description.name,"ingress.updatePit_entry");

    netconv_p4_header(h);
    netconv_p4_add_table_entry(te);
    netconv_p4_field_match_exact(exact);
    netconv_p4_action(a);
    send_p4_msg(c, buffer, 2048);
    usleep(1200);
}


void set_default_action_section_table()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;


    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "ingress.section_table_0");

    a = &(sda->action);
    strcpy(a->description.name, "ingress._drop");

    netconv_p4_header(h);
    netconv_p4_set_default_action(sda);
    netconv_p4_action(a);

    send_p4_msg(c, buffer, sizeof(buffer));
}

void set_default_action_count_table()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;


    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "ingress.count_table_0");

    a = &(sda->action);
    strcpy(a->description.name, "ingress._drop");

    netconv_p4_header(h);
    netconv_p4_set_default_action(sda);
    netconv_p4_action(a);

    send_p4_msg(c, buffer, sizeof(buffer));
}

void set_default_action_fib_table()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;


    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "ingress.fib_table_0");

    a = &(sda->action);
    strcpy(a->description.name, "ingress._drop");

    netconv_p4_header(h);
    netconv_p4_set_default_action(sda);
    netconv_p4_action(a);

    send_p4_msg(c, buffer, sizeof(buffer));
}

void set_default_action_updatePit_table()
{
    char buffer[2048];
    struct p4_header* h;
    struct p4_set_default_action* sda;
    struct p4_action* a;


    h = create_p4_header(buffer, 0, sizeof(buffer));

    sda = create_p4_set_default_action(buffer,0,sizeof(buffer));
    strcpy(sda->table_name, "ingress.updatePit_table_0");

    a = &(sda->action);
    strcpy(a->description.name, "ingress._drop");

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
    uint8_t valid[5];
    // _Bool valid1;
    // _Bool valid2;
    // _Bool valid3;
    // _Bool valid4;
    uint8_t isvalid;
    uint8_t is_valid;
    uint16_t isvalid1[6];
    uint8_t isvalid2;
    char pit_valid;
    // uint8_t isvalid3;
    // uint8_t isvalid4;
    uint8_t isvalid5;
    // uint8_t isvalid6;

    char dummy;
    FILE *f;
    f = fopen(filename,"r");
	if (f == NULL) return -1;

    int line_index = 0;
	while (fgets(line,sizeof(line),f)){
        line[strlen(line)-1] = '\0';
		line_index++;
		printf("Sor:%d.",line_index);
        if(line[0]== 'A'){
            if(2==sscanf(line,"%c %d",&dummy,&isvalid)){
                
                fill_section_table_table(isvalid);
            }
            else{
                fclose(f);
                return -1;
            }
        }
        else if(line[0]=='B'){
            if(7 == sscanf(line,"%c %d %d %d %d %d %hhd",&dummy,&valid[0],&valid[1],&valid[2],&valid[3],&valid[4],&isvalid5)){
                fill_count_table_table(valid,isvalid5);
            }
            else{
                fclose(f);
                return -1;
            }
        }
        else if(line[0]=='C'){
            // fp6 = fopen("/home/zjlab/log/fenpian.txt","a");
        //  if(fp6){
	 	//  fprintf(fp6,"bbb:%d",sscanf(line,"%c %hhd %hhx %hhx %hhx %hhx %hhx %hhd",&dummy,&isvalid,&isvalid1,&isvalid2,&isvalid3,&isvalid4,&isvalid5,&isvalid6));
        //          fprintf(fp6,"\n");
        //          fclose(fp6);
        //      }
            if(8 == sscanf(line,"%c %hhd %x %x %x %x %x %hhd",&dummy,&isvalid,&isvalid1[0],&isvalid1[1],&isvalid1[2],&isvalid1[3],&isvalid1[4],&isvalid2)){
                fp6 = fopen("/home/zjlab/log/fenpian.txt","a");
                if(fp6){
	 	            fprintf(fp6,"bbb:%x %x",isvalid1[2],isvalid1[4]);
                    fprintf(fp6,"\n");
                    fclose(fp6);
                }
                fill_fib_table_table(isvalid,isvalid1,isvalid2);
                
            }
            else{
                fclose(f);
                return -1;
            }
        }
        else if(line[0]== 'D'){
            if(3 == sscanf(line,"%c %hhx %hhd",&dummy,&pit_valid,&is_valid)){
                fill_pit_table_table(pit_valid,is_valid);
            }
            else{
                fclose(f);
                return -1;
            }
        }
        else if(line[0]== 'E'){
            if(2 == sscanf(line,"%c %hhd",&dummy,&isvalid)){
                fill_updatecs_table_table(isvalid);
            }
            else{
                fclose(f);
                return -1;
            }
        }
        else if(line[0]== 'F'){
            if(2 == sscanf(line,"%c %hhd",&dummy,&isvalid)){
                fill_updatePit_table_table(isvalid);
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
	// set_default_action_section_table();
    // set_default_action_count_table();
    // set_default_action_fib_table();
    // set_default_action_updatePit_table();

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
        printf("--------init field------");
	}

    notify_controller_initialized();

	execute_controller(c);

	destroy_controller(c);

	return 0;
}