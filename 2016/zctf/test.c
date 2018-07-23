/*
House of force vulnerable program.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;        // <=== 这里把top chunk的size域改为0xffffffffffffffff
    malloc(-7420);  // <=== 减小top chunk指针
    malloc(0x10);   // <=== 分配块实现任意地址写
}