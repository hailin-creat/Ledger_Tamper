#include <stdio.h>
#include <string.h>

int check_password(const char *pwd) {
    // Correct password
    return strcmp(pwd, "123456") == 0;
}

void do_sensitive_action() {
    printf("[SecureApp] Sensitive operation executed!\n");
}

int main() {
    char input[100];
    printf("Please enter password: ");
    scanf("%99s", input);

    if (check_password(input)) {
        do_sensitive_action();
    } else {
        printf("[SecureApp] Incorrect password, access denied.\n");
    }

    return 0;
}
