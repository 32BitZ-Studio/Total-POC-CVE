/*
    Source code of ./exp/bin/keep
    A process which is running on the host and to be killed
*/
#include <stdio.h>
#include <unistd.h>

int main()
{
    const int sleep_time = 600;
    printf("My process ID is: %d\nPut this number to `PID` in the sendsig.c and compile!\n I will be here waiting for %d seconds.", getpid(), sleep_time);
    sleep(sleep_time);
    return 0;
}