#include<stdio.h>
#include<malloc.h>
#include<string.h>





int main()
{


    for(int i=0;i<8;i++)
    {
        int alloc_size=8*i+4;
        int chunk_size=(alloc_size+7)/8*8;
        chunk_size=chunk_size<16?16:chunk_size;
        char *p1,*p2,*p3,*p4;

        p1=(char*)malloc(alloc_size);
        p2=(char*)malloc(alloc_si2ze);
        p3=(char*)malloc(alloc_size);
        p4=(char*)malloc(alloc_size);

        printf("alloc_size:%d,chunk_size:%d,p1:%08x,p2:%08x,p3:%08x,p4:%08x\n",alloc_size,chunk_size,p1,p2,p3,p4);
        memset(p1,'a',alloc_size);
        memset(p2,'b',alloc_size);
        memset(p3,'c',alloc_size);
        memset(p4,'d',alloc_size);

        free(p2);
        free(p3);

    }

    return 0;
}