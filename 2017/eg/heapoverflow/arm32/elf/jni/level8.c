#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

void getsystemaddr()
{
    void* handle = dlopen("libc.so", RTLD_LAZY);
    printf("%p\n",dlsym(handle,"system"));
    fflush(stdout);
}

void vulnerable_function() {
    char buf[128];
    read(STDIN_FILENO, buf, 256);
}
 
int main(int argc, char** argv) {
    getsystemaddr();
    write(STDOUT_FILENO, "Hello, World\n", 13);    
    vulnerable_function();
}

