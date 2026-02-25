/*
    Here is the source code of `sendsig` used in the simple exploit section.
    You have to modify the PID manually according to what `keep` display while running.
*/
#include <signal.h>
#include <stdio.h>

int main() {
    int pid = 7719; // Remember to modify according to the PID displayed by the `keep` process before compiling!
    if (kill(pid, SIGKILL) == 0) {
        printf("SIGKILL signal sent to process %d\n", pid);
    } else {
        perror("kill");
    }
    return 0;
}