#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "xnumem.h"

int main (int argc, const char * argv[]) {
    
	printf("Starting\n");
	int i;
	i = 12;
	size_t size = sizeof(int);
	
	unsigned char* buffer = xnu_read(getpid(), &i, &size);
	printf("%i\n",(int)*buffer);
	
	unsigned char* data = malloc(sizeof(int));
	*data = 17;
	
	xnu_write(getpid(), &i, data, sizeof(int));
	
	buffer = xnu_read(getpid(), &i, &size);
	printf("%i\n",(int)*buffer);

	getchar();
    return 0;
}
