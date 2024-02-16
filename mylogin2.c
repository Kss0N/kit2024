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
#include <signal.h>

#define USERNAME_SIZE (32)
#define NOUSER (-1)
#define SALT_LEN 2
#define OLD_AGE 10
#define MAX_FAIL 5
#define ROOT_UID 0
#define RESET_PASSWORD_FLAG "--reset"

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
}

/* Resets password of username name. this MUST only be called by root user with flags
`--reset` followed by username to reset password
then it will ask for a new password and that will be the new password
lastly the pw_failed counter will be reset back to 0
*/
int reset_password(const char* name)
{
    struct pwdb_passwd* p_pw = pwdb_getpwnam(name);
    if (!p_pw) {
        if (pwdb_errno == PWDB_NOUSER) goto USER_NOT_FOUND;
    }

    char* new_pw = getpass("Enter new password: ");
    char salt[SALT_LEN + 1];
    memcpy(salt, p_pw->pw_passwd, SALT_LEN);
    salt[SALT_LEN] = '\0';

    p_pw->pw_passwd = crypt(new_pw, salt);
    p_pw->pw_failed = 0;
    pwdb_update_user(p_pw);

    return 0;

USER_NOT_FOUND:
    printf("User with name %s is not part of the database\n", name);
    return -1;
}

#define XTERM_PATH "/usr/bin/xterm"

static int on_success(const char* username, const struct pwdb_passwd* p_pwf)
{
    pid_t pid;
    int status;

    pid = fork();

    if (pid == 0) {
        /* This is the child process. Run an xterm window */
        execl(XTERM_PATH, XTERM_PATH, "-e", p_pwf->pw_shell, "-l", NULL);

        /* if child returns we must inform parent.
        * Always exit a child process with _exit() and not return() or exit().
        */
        _exit(-1);
    }
    else if (pid < 0) { /* Fork failed */
        printf("Fork faild\n");
        status = -1;
    }
    else {
        /* This is parent process. Wait for child to complete */
        if (waitpid(pid, &status, 0) != pid) {
            status = -1;
        }
    }

    return status;
}


int main(int argc, char** argv)
{
    int retval = 0;
    if (argc == 3 &&
        getuid() == ROOT_UID &&
        strcmp(argv[1], RESET_PASSWORD_FLAG) == 0)
    {
        return reset_password(argv[2]);
    }

    signal(SIGINT, SIG_IGN);

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
        if (p_pwf->pw_failed >= 5)
            goto LOCKOUT;

        char salt[SALT_LEN + 1];
        memcpy(salt, p_pwf->pw_passwd, SALT_LEN);
        salt[SALT_LEN] = '\0';
        assert(strlen(salt) == SALT_LEN);

        if (strcmp(p_pwf->pw_passwd, crypt(password, salt)) == 0) {
            ;
            break;
        }

    FAIL:
        if (p_pwf) {
            p_pwf->pw_failed++;
            pwdb_update_user(p_pwf);
        }
        printf("Unknown user or incorrect password!\n");
        continue;
    }

    printf("User authenticated successfully\n");

    p_pwf->pw_failed = 0;
    p_pwf->pw_age++;
    pwdb_update_user(p_pwf);

    if (p_pwf->pw_age > OLD_AGE) {
        printf("You have logged in more than %d times, consider changing password\n",
            OLD_AGE);
    }

    retval = on_success(username, p_pwf);

END:
    free(p_pwf);
    return retval;
LOCKOUT:
    printf("You have failed authentication more than %d, you have been locked out. Contact administrator.\n", MAX_FAIL);
    goto END;
}
