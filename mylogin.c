/*
 * Shows user info from local pwfile.
 *
 * Usage: userinfo username
 */
#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pwdblib.h"   /* include header declarations for pwdblib.c */
#include <crypt.h>
#include <stdbool.h>
#include <assert.h>

#define USERNAME_SIZE (32)
#define NOUSER (-1)
#define SALT_LEN 2

int print_info(const char* username)
{
    struct pwdb_passwd* p = pwdb_getpwnam(username);
    if (p != NULL) {
        printf("Name: %s\n", p->pw_name);
        printf("Passwd: %s\n", p->pw_passwd);
        printf("Uid: %u\n", p->pw_uid);
        printf("Gid: %u\n", p->pw_gid);
        printf("Real name: %s\n", p->pw_gecos);
        printf("Home dir: %s\n", p->pw_dir);
        printf("Shell: %s\n", p->pw_shell);
        return 0;
    }
    else {
        return NOUSER;
    }
}

/*
   * Write "login: " and read user input. Copies the username to the
   * username variable.
   */
void read_username(char* username)
{
    (void)printf("login: ");
    fgets(username, USERNAME_SIZE, stdin);

    /* remove the newline included by getline() */
    username[strlen(username) - 1] = '\0';

    return username;
}

int main(int argc, char** argv)
{
    char username[USERNAME_SIZE];

    // password file entry corresponding to username
    struct pwdb_passwd* p_pwf;

    while (true)
    {
        read_username(username);
        char* password = getpass("Enter password: ");

        p_pwf = pwdb_getpwnam(username);
        if (!p_pwf) {
            goto FAIL;
        }
        char salt[SALT_LEN + 1];
        memcpy(salt, p_pwf->pw_passwd, SALT_LEN);
        salt[SALT_LEN] = '\0';
        assert(strlen(salt) == SALT_LEN);

        if (strcmp(p_pwf->pw_passwd, crypt(password, salt)) == 0) {
            printf("User authenticated successfully\n");
            break;
        }

    FAIL:
        printf("Unknown user or incorrect password!\n");
        continue;
    }

    free(p_pwf);
    return 0;
}
