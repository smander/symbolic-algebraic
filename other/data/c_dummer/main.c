#include <stdio.h>
#include <dlfcn.h>

int main() {
    void *handle;
    int (*library_function)(int);
    char *error;

    // Load the shared library
    handle = dlopen("./libexternal.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 1;
    }

    // Clear any existing errors
    dlerror();

    // Get a pointer to the library function
    *(void **)(&library_function) = dlsym(handle, "library_function");

    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "%s\n", error);
        return 1;
    }

    // Use the function
    int input;
    printf("Enter a number: ");
    scanf("%d", &input);
    int result = library_function(input);

    // Close the library
    dlclose(handle);

    return result;
}
