
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <string>

using namespace std;

void dumpmem()
{
    pid_t pid = getpid();

    uint64_t totallength = 0;

    char pidstr[10];
    sprintf(pidstr, "%d", pid);

    string mappath = string("/proc/") + pidstr + "/maps";
    FILE* fd = fopen(mappath.c_str(), "r");

    FILE* out = fopen("hashword.dump", "w");

    while (!feof(fd))
    {
        // 00703000-0070c000 rw-p 00103000 08:01 13                                 /bin/bash
        char line[1024];
        int res;

        if (fgets(line, 1023, fd) == NULL)
        {
            break;
        }

        uint64_t start;
        uint64_t end;
        char rflag;
        char wflag;

        res = sscanf(line, "%llx-%llx %c%c", &start, &end, &rflag, &wflag);
        if (res != 4)
        {
            continue;
        }

        int len = strlen(line);
        if (line[len - 1] == '\n')
        {
            line[len - 1] = 0;
        }

/*
        printf("line: %s\n", line);
*/

        bool readable = (rflag == 'r');
        bool writeable = (wflag == 'w');

        if (!readable || !writeable)
        {
            continue;
        }

        uint64_t regionlen = (end - start) - 1;
        totallength += regionlen;

/*
        printf(
            "    range: 0x%llx - 0x%llx (length=%lld), readable=%d, writeable=%d\n", start, end, regionlen, readable, writeable);
*/

        void* ptr = (void*)start;
        fwrite(ptr, regionlen, 1, out);

    }

/*
    printf("Total length: %lld\n", totallength);
*/

    fclose(out);
    fclose(fd);
}

#if 0
int main(int argc, char** argv)
{
    memscan();
    return 0;
}
#endif

