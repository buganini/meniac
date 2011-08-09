/*
# ./bigwet `pidof dummy`
bigwet> search 0 int32 54321
Searching integer 54321:(omni)
(0x8048508)     54321
(0x8049508)     54321
(0xbfbfe3f4)    54321
(0xbfbfea64)    54321
bigwet> set 0x8048508 int32 12345
bigwet> quit
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <errno.h>

#define PTRACE_ARG3_T caddr_t

#define TP_INT8 -1
#define TP_INT16 -2
#define TP_INT32 -4
#define TP_INT64 -8
#define TP_UINT8 1
#define TP_UINT16 2
#define TP_UINT32 4
#define TP_UINT64 8

#define omnisearch(type) while(fgets(str,1024,fp)!=0){			\
	sscanf(str,"%x%x%s%s%s%s%s%s%s%s%s%s%s",&start,&end,null,null,null,null,null,null,null,null,null,null,path);	\
	if(strncmp("/lib",path,4)==0 || strncmp("/usr/lib",path,8)==0 || strncmp("/usr/local/lib",path,14)==0){		\
		printf("Skipping %s section\n",path);		\
		continue;						\
	}							\
	for(ptr=start;ptr<end;++ptr){				\
		ioreq.piod_op=PIOD_READ_D;			\
		ioreq.piod_offs=ptr;				\
		ioreq.piod_addr=&sample;				\
		ioreq.piod_len=abs(type);				\
		ptrace(PT_IO, pid, (PTRACE_ARG3_T) &ioreq, 0);			\
		if(memcmp(&sample,&target,abs(type))==0){	\
			addlist(ptr, sample);			\
		}						\
	}							\
}

#define scopesearch(type) while(tmp!=0){				\
		ioreq.piod_op=PIOD_READ_D;			\
		ioreq.piod_offs=tmp->addr;			\
		ioreq.piod_addr=&(tmp->value);			\
		ioreq.piod_len=abs(type);				\
		ptrace(PT_IO, pid, (PTRACE_ARG3_T) &ioreq, 0);			\
		if(memcmp(&(tmp->value),&target,abs(type))!=0){	\
			dellist(tmp);				\
		}						\
		tmp=tmp->next;					\
	}

typedef union {
	int_least8_t int8;
	int_least16_t int16;
	int_least32_t int32;
	int_least64_t int64;
	uint_least8_t uint8;
	uint_least16_t uint16;
	uint_least32_t uint32;
	uint_least64_t uint64;
	unsigned char byte[8];
} block;

struct addrlist_u {
	int addr;
	block value;
	struct addrlist_u * next;
};

typedef struct addrlist_u addrlist;

int print();
int search();
int addlist(int addr, block data);
int dellist(addrlist *ptr);
int set();
int reset();
int detach();
int end();

int tracing=0;
struct ptrace_io_desc ioreq;
addrlist *threads[8]={0};
addrlist *final_scope[8];
int pid, thread, type, value;
char cmd[10], second[20], datatype[10];
char cmdbuf[1024];

int main(int argc, char *argv[]){
	block addr;
	if(argc!=2){
		return 1;
	}
	pid=atoi(argv[1]);
	if(attach()<0){
		fprintf(stderr, "Unable to attach.\n");
		exit(1);
	}
	while(1){
		printf("bigwet> ");
		fgets(cmdbuf,1024,stdin);
		if(sscanf(cmdbuf,"%s%s%s%d", cmd, second, datatype, &value)==0) continue;
		if(strcmp("int8",datatype)==0){
			type=TP_INT8;
		}else if(strcmp("int16",datatype)==0){
			type=TP_INT16;
		}else if(strcmp("int32",datatype)==0){
			type=TP_INT32;
		}else if(strcmp("int64",datatype)==0){
			type=TP_INT64;
		}else if(strcmp("uint8",datatype)==0){
			type=TP_UINT8;
		}else if(strcmp("uint16",datatype)==0){
			type=TP_UINT16;
		}else if(strcmp("uint32",datatype)==0){
			type=TP_UINT32;
		}else if(strcmp("uint64",datatype)==0){
			type=TP_UINT64;
		}
		if(strcmp("search",cmd)==0){
			if(!tracing) attach();
			search();
			print();
		}else if(strcmp("set",cmd)==0){
			if(!tracing) attach();
			set();
		}else if(strcmp("reset",cmd)==0){
			reset();
		}else if(strcmp("print",cmd)==0){
			print();
		}else if(strcmp("continue",cmd)==0){
			detach();
		}else if(strcmp("pause",cmd)==0){
			attach();
		}else if(strcmp("help",cmd)==0){
			printf(
				"continue\n"
				"pause\n"
				"search 0 type value (0 is place holder)\n"
				"set address type value\n"
				"reset\n"
				"quit\n"
				"\n"
				"Type: [u]int{8,16,32,64}\n"
			);
		}else if(strcmp("quit",cmd)==0){
			detach();
			break;
		}
	}
	return 0;
}

int attach(){
	int ret;
	if(tracing==1){
		return -1;
	}
	tracing=1;
	ret=ptrace(PT_ATTACH, pid, (PTRACE_ARG3_T) 0, 0);
	if(ret<0){
		return ret;
	}
	wait(NULL);
	return ret;
}

int detach(){
	if(tracing==0){
		return -1;
	}
	tracing=0;
	return ptrace(PT_DETACH, pid, (PTRACE_ARG3_T) 1, 0);
}

int print(){
	addrlist *tmp;
	int i;
	sscanf(second,"%d",&thread);
	printf("Thread[%d]:\n",thread);
	tmp=threads[thread];
	while(tmp!=0){
		printf("( %p )\t", tmp->addr);
		for(i=0;i<8;++i){
			printf("%X ",(tmp->value).byte[i]);
		}
		printf("\n");
		tmp=tmp->next;
	}
	return 0;
}

int search(){
	block target, sample;
	addrlist *tmp;
	sscanf(second,"%d",&thread);
	tmp=threads[thread];
	
	char str[1024], path[512];
	FILE *fp;
	char procmap[20], null[10];
	int start, end;
	sprintf(procmap,"procmap %d",pid);
	fp=popen(procmap,"r");
	if(fp==0){
		exit(1);
	}
	int ptr=0;
	if(type==TP_INT8){
		target.int8=value;
		printf("Searching int8 %d:",target.int8);
		if(threads[thread]==0){
			printf("(omni)\n");
			omnisearch(type)
		}else{
			putchar('\n');
			scopesearch(type);
		}
	}else if(type==TP_UINT8){
		target.uint8=value;
		printf("Searching uint8 %d:",target.uint8);
		if(threads[thread]==0){
			printf("(omni)\n");
			omnisearch(type)
		}else{
			putchar('\n');
			scopesearch(type);
		}
	}else	if(type==TP_INT16){
		target.int16=value;
		printf("Searching int16 %d:",target.int16);
		if(threads[thread]==0){
			printf("(omni)\n");
			omnisearch(type)
		}else{
			putchar('\n');
			scopesearch(type);
		}
	}else if(type==TP_UINT16){
		target.uint16=value;
		printf("Searching uint16 %d:",target.uint16);
		if(threads[thread]==0){
			printf("(omni)\n");
			omnisearch(type)
		}else{
			putchar('\n');
			scopesearch(type);
		}
	}else if(type==TP_INT32){
		target.int32=value;
		printf("Searching int32 %d:",target.int32);
		if(threads[thread]==0){
			printf("(omni)\n");
			omnisearch(type)
		}else{
			putchar('\n');
			scopesearch(type);
		}
	}else if(type==TP_UINT32){
		target.uint32=value;
		printf("Searching uint32 %d:",target.uint32);
		if(threads[thread]==0){
			printf("(omni)\n");
			omnisearch(type)
		}else{
			putchar('\n');
			scopesearch(type);
		}
	}
	fclose(fp);
}

int set(){
	int addr;
	block data;
	sscanf(second,"%p",&addr);
	if(type==TP_INT8){
		data.int8=value;
	}else if(type==TP_INT16){
		data.int16=value;
	}else if(type==TP_INT32){
		data.int32=value;
	}else if(type==TP_INT64){
		data.int64=value;
	}else if(type==TP_UINT8){
		data.uint8=value;
	}else if(type==TP_UINT16){
		data.uint16=value;
	}else if(type==TP_UINT32){
		data.uint32=value;
	}else if(type==TP_UINT64){
		data.uint64=value;
	}else{
		return;
	}
	ioreq.piod_op=PIOD_WRITE_D;
	ioreq.piod_offs=addr;
	ioreq.piod_addr=&data;
	ioreq.piod_len=abs(type);
	ptrace(PT_IO, pid, (PTRACE_ARG3_T) &ioreq, 0);
	return 0;
}

int addlist(int addr, block data){
	addrlist *tmp;
	if(threads[thread]==0){
		final_scope[thread]=threads[thread]=malloc(sizeof(addrlist));
	}else{
		final_scope[thread]->next=malloc(sizeof(addrlist));
		final_scope[thread]=final_scope[thread]->next;
	}
	final_scope[thread]->addr=addr;
	final_scope[thread]->value=data;
	final_scope[thread]->next=0;
	return 0;
}

int dellist(addrlist *ptr){
	addrlist *tmp=threads[thread];
	if(threads[thread]==0){
		return 0;
	}
	if(threads[thread]==ptr){
		tmp=threads[thread]->next;
		free(threads[thread]);
		threads[thread]=tmp;
	}else{
		while(tmp->next!=ptr){
			tmp=tmp->next;
		}
		tmp->next=ptr->next;
		free(ptr);
	}
	return 0;
}

int reset(){
	addrlist *tmp;
	sscanf(second,"%d",&thread);
	while(threads[thread]!=0){
		tmp=threads[thread]->next;
		free(threads[thread]);
		threads[thread]=tmp;
	}
	return 0;
}
