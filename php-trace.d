#!/usr/sbin/dtrace -Zs

#pragma D option quiet

php*:::compile-file-entry
{
    printf("PHP compile-file-entry compile_file: %s\n", copyinstr(arg0));
    /* printf("  compile_file_translated   %s\n", copyinstr(arg1)); */
}

php*:::compile-file-return
{
    /*
    printf("PHP compile-file-return\n");
    printf("  compile_file              %s\n", copyinstr(arg0));
    printf("  compile_file_translated   %s\n", copyinstr(arg1));
    */
}

php*:::error
{
    printf("PHP error: errormsg %s in %s:%d\n", copyinstr(arg0), copyinstr(arg1), (int)arg2);
}

php*:::exception-caught
{
    printf("PHP exception-caught in classname: %s\n", copyinstr(arg0));
}

php*:::exception-thrown
{
    printf("PHP exception-thrown in classname: %s\n", copyinstr(arg0));
}

php*:::execute-entry
{
    printf("PHP execute-entry in: %s:%d\n", copyinstr(arg0), (int)arg1);
}

php*:::execute-return
{
    /*
    // printf("PHP execute-return\n");
    // printf("  request_file              %s\n", copyinstr(arg0));
    // printf("  lineno                    %d\n", (int)arg1);
    */
}

php*:::function-entry
{
    printf("PHP function-entry:  %s %s() in %s:%d\n", copyinstr(arg3), copyinstr(arg0), copyinstr(arg1), (int)arg2);
    /*
    // printf("PHP function-entry\n");
    // printf("  function_name             %s\n", copyinstr(arg0));
    // printf("  request_file              %s\n", copyinstr(arg1));
    // printf("  lineno                    %d\n", (int)arg2);
    // printf("  classname                 %s\n", copyinstr(arg3));
    // printf("  scope                     %s\n", copyinstr(arg4));
    */
}

php*:::function-return
{
    printf("PHP function-return: %s() in %s:%d\n", copyinstr(arg0), copyinstr(arg1), (int)arg2);
    /*
    // printf("PHP function-return\n");
    // printf("  function_name             %s\n", copyinstr(arg0));
    // printf("  request_file              %s\n", copyinstr(arg1));
    // printf("  lineno                    %d\n", (int)arg2);
    // printf("  classname                 %s\n", copyinstr(arg3));
    // printf("  scope                     %s\n", copyinstr(arg4));
    */
}

php*:::request-shutdown
{
    printf("Shutdown request in: %s\n", copyinstr(arg0));
    /*
    // printf("PHP request-shutdown\n");
    // printf("  file                      %s\n", copyinstr(arg0));
    // printf("  request_uri               %s\n", copyinstr(arg1));
    // printf("  request_method            %s\n", copyinstr(arg2));
    */
}

php*:::request-startup
{
    printf("PHP request-startup in %s\n", copyinstr(arg0));
    /*
    printf("  file                      %s\n", copyinstr(arg0));
    printf("  request_uri               %s\n", copyinstr(arg1));
    printf("  request_method            %s\n", copyinstr(arg2));
    */
}
