#include "stdio.h"
#include "time.h"
#include "string.h"

int main()
{
    int seed=10;
    srand(seed);
    unsigned int randvalue[30]={0};
    char result[100];
    int len;
    int i=0;
    //printf("%x\n",rand());
    for(i=0;i<=29;i++)
    {
        randvalue[i]=rand()%1000;
        printf("%x\n",randvalue[i]);
        sprintf(result,"%d",randvalue[i]);
        printf("%s\n",result);
        len=strlen(result);
        printf("%d\n",len);

    }
    printf("%x\n",randvalue[i]);
    return 1;
}