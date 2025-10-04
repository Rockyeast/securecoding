#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define USER_MAX 40
#define DOMAIN_MAX 64
#define FLAGSIZE 128

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  fgets(buf,FLAGSIZE,f);
  puts(buf);
  fflush(stdout);
}

void print_email_address(char *TheUser, char * TheDomain) {
   char rpath[USER_MAX+DOMAIN_MAX+2];
   strncpy( rpath, TheUser, USER_MAX );
   strncat( rpath, "@", 1 );
   strncat( rpath, TheDomain, DOMAIN_MAX );
   printf("%s\n",rpath);
}
void vuln(){
   char user[USER_MAX+1];
   char domain[DOMAIN_MAX+1];
   char user2[USER_MAX+1];
   char domain2[DOMAIN_MAX+1];
   int len;
   printf("Enter a username (up to %d chars):", USER_MAX);
   fgets(user,USER_MAX+1,stdin);
   len = strlen(user);
   if (user[len-1]=='\n') {
      user[len-1]='\0';
   }
   printf("Enter a domainname (up to %d chars):", DOMAIN_MAX);
   fgets(domain,DOMAIN_MAX+1,stdin);
   len = strlen(domain);
   if (domain[len-1]=='\n') {
      domain[len-1]='\0';
   }
   printf("Enter a second username (up to %d chars):", USER_MAX);
   fgets(user2,USER_MAX+1,stdin);
   len = strlen(user2);
   if (user2[len-1]=='\n') {
      user2[len-1]='\0';
   }
   printf("Enter a second domainname (up to %d chars):", DOMAIN_MAX);
   fgets(domain2,DOMAIN_MAX+1,stdin);
   len = strlen(domain2);
   if (domain2[len-1]=='\n') {
      domain2[len-1]='\0';
   }
   print_email_address(user,domain);
   print_email_address(user2,domain2);
}

int main(int argc, char **argv){
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  int i;
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  return 0;
}
