#include <stdio.h>
#include <string.h>

int check_password(const char *pwd) {
    // 正确密码
    return strcmp(pwd, "123456") == 0;
}

void do_sensitive_action() {
    printf("[SecureApp] 已执行敏感操作！\n");
}

int main() {
    char input[100];
    printf("请输入密码: ");
    scanf("%99s", input);

    if (check_password(input)) {
        do_sensitive_action();
    } else {
        printf("[SecureApp] 密码错误，拒绝执行。\n");
    }

    return 0;
}
