#!/usr/sbin/dtrace -Zs

#pragma D option quiet

php*:::compile-file-entry
{
    printf("%Y: PHP compile-file-entry:\t%s (%s)\n", walltimestamp, basename(copyinstr(arg0)), copyinstr(arg1));
}

php*:::compile-file-return
{
    printf("%Y: PHP compile-file-return:\t%s (%s)\n", walltimestamp, basename(copyinstr(arg0)), basename(copyinstr(arg1)));
}

php*:::error
{
    printf("%Y: PHP error message:\t%s in %s:%d\n", walltimestamp, copyinstr(arg0), basename(copyinstr(arg1)), (int)arg2);
}

php*:::exception-caught
{
    printf("%Y: PHP exception-caught:\t%s\n", walltimestamp, copyinstr(arg0));
}

php*:::exception-thrown
{
    printf("%Y: PHP exception-thrown:\t%s\n", walltimestamp, copyinstr(arg0));
}

php*:::execute-entry
{
    printf("%Y: PHP execute-entry:\t%s:%d\n", walltimestamp, basename(copyinstr(arg0)), (int)arg1);
}

php*:::execute-return
{
    printf("%Y: PHP execute-return:\t%s:%d\n", walltimestamp, basename(copyinstr(arg0)), (int)arg1);
}

php*:::function-entry
{
    printf("%Y: PHP function-entry:\t%s%s%s() in %s:%d\n", walltimestamp, copyinstr(arg3), copyinstr(arg4), copyinstr(arg0), basename(copyinstr(arg1)), (int)arg2);
}

php*:::function-return
{
    printf("%Y: PHP function-return:\t%s%s%s() in %s:%d\n", walltimestamp, copyinstr(arg3), copyinstr(arg4), copyinstr(arg0), basename(copyinstr(arg1)), (int)arg2);
}

php*:::request-shutdown
{
    printf("%Y: PHP request-shutdown:\t%s at %s via %s\n", walltimestamp, basename(copyinstr(arg0)), copyinstr(arg1), copyinstr(arg2));
}

php*:::request-startup
{
    printf("%Y, PHP request-startup:\t%s at %s via %s\n", walltimestamp, basename(copyinstr(arg0)), copyinstr(arg1), copyinstr(arg2));
}
