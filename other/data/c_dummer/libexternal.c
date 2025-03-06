#include <stdio.h>

int library_function(int input) {
    if (input == 42) {
        printf("Correct input!\n");
        return 1;
    } else {
        printf("Wrong input!\n");
        return 0;
    }
}
