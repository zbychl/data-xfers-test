#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "main.h"


int main(int argc, char* argv[])
{
    while(1)
    {
        printf("Hello Word!\n");
        fflush(NULL);
        usleep(1000000);
    }

    return 0;
}

