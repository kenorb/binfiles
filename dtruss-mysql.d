#!/usr/sbin/dtrace -q
# Usage: dtrace -s watch.d -p `pgrep -x mysqld`
# See: https://dev.mysql.com/tech-resources/articles/getting_started_dtrace_saha.html

mysql*:::query-start /* using the mysql provider */
{

  self->query = copyinstr(arg0); /* Get the query */
  self->connid = arg1; /*  Get the connection ID */
  self->db = copyinstr(arg2); /* Get the DB name */
  self->who   = strjoin(copyinstr(arg3),strjoin("@",copyinstr(arg4))); /* Get the username */

  printf("%Y\t %20s\t  Connection ID: %d \t Database: %s \t Query: %s\n", walltimestamp, self->who ,self->connid, self->db, self->query);

}

pid$target::*mysql_parse*:entry /* This probe is fired when the execution enters mysql_parse */
{
     printf("Query: %s\n", copyinstr(arg1));

}

pid$target::*mysql_parse*:entry
{
   self->start = vtimestamp;

}
pid$target:::entry
/self->start/
{
   trace(timestamp);

}

pid$target:::return
/self->start/
{
   trace(timestamp);
}
pid$target::*mysql_parse*:return
/self->start/
{

   self->start = 0;

}
