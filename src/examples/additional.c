/* additional.c

   Prints the result of 'fibonacci' system call to the console, 
   using arg1 as parameter. 
   Prints the result of 'max_of_four_int' system call to the console, 
   using arg1-4 as parameters. */

#include <stdio.h>
#include <syscall.h>

static int atoi(const char* str);

int
main(int argc, char* argv[])
{
    if (argc != 5)
    {
        printf("%s: open failed\n", argv[0]);
        exit(-1);
    }

    printf("%d %d\n", fibonacci(atoi(argv[1])), max_of_four_int(
        atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), atoi(argv[4])));

    return 0;
}

/* My atoi function that produces a number indicated by string */
int 
atoi(const char* str)
{
    int num = 0, i = 0;

    while (str[i] && (str[i] >= '0' && str[i] <= '9'))
    {
        num = num * 10 + (str[i] - '0');
        i++;
    }

    return num;
}
