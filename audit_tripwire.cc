#include <stdio.h>
#include <string.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <mysql/service_my_plugin_log.h>
#include <mysql/service_security_context.h>

static char *audit_tripwire_table_value= NULL;
static char *audit_tripwire_db_value= NULL;
static my_bool panic_mode_value= FALSE;

static MYSQL_PLUGIN plugin= NULL;

static bool is_super(MYSQL_THD thd)
{
  MYSQL_SECURITY_CONTEXT ctx;
  my_svc_bool is_super= FALSE;

  /* setting panic mode requires super */
  return (
    thd != NULL &&
    !thd_get_security_context(thd, &ctx) &&
    !security_context_get_option(ctx, "privilege_super", &is_super) &&
    is_super);
}


static int
audit_tripwire_notify(MYSQL_THD thd,
                      mysql_event_class_t event_class,
                      const void *event)
{
  /* if we're in panic mode stop all commands from non-supers */
  if (panic_mode_value && !is_super(thd))
    return TRUE;

  /* Check if the table (if specified) is accessed */
  if (event_class == MYSQL_AUDIT_TABLE_ACCESS_CLASS &&
      (audit_tripwire_table_value || audit_tripwire_db_value))
  {
    const struct mysql_event_table_access *table_access=
      (const struct mysql_event_table_access *)event;

    if (!is_super(thd))
    {
      /* check for a matching table name */
      if (audit_tripwire_table_value &&
          strncmp(table_access->table_name.str,
                  audit_tripwire_table_value,
                  table_access->table_name.length))
        return FALSE;

      /* check for a matching database name */
      if (audit_tripwire_db_value &&
          strncmp(table_access->table_database.str,
                  audit_tripwire_db_value,
                  table_access->table_database.length))
        return FALSE;

      /* table is accessed. Time to panic ! */
      my_plugin_log_message(&plugin, MY_WARNING_LEVEL,
                            "Tripwire table `%s`.`%s` accessed from "
                            "connection id %d. Switching to panic mode",
                            audit_tripwire_db_value ?
                              audit_tripwire_db_value : "*",
                            audit_tripwire_table_value ?
                            audit_tripwire_table_value : "*",
                            table_access->connection_id
                            );
      panic_mode_value= TRUE;
      return TRUE;
    }
  }

  return FALSE;
}


static struct st_mysql_audit audit_tripwire_descriptor=
{
  MYSQL_AUDIT_INTERFACE_VERSION,                    /* interface version    */
  NULL,                                             /* release_thd function */
  audit_tripwire_notify,                            /* notify function      */
  {
    0,                                              /* general */
    0,                                              /* connection */
    0,                                              /* parse */
    0,                                              /* authorization */
    MYSQL_AUDIT_TABLE_ACCESS_ALL,                   /* table access */
    0,                                              /* global variables */
    0,                                              /* server startup */
    0,                                              /* server shutdown */
    MYSQL_AUDIT_COMMAND_START,                      /* command */
    0,                                              /* query */
    0                                               /* stored program */
  }
};

/* plumbing */

static MYSQL_SYSVAR_STR(
  table,                                                       /* name       */
  audit_tripwire_table_value,                                  /* value      */
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,                   /* flags      */
  "Table to watch for.",                                       /* comment    */
  NULL,                                                        /* check()    */
  NULL,                                                        /* update()   */
  NULL                                                         /* default    */
);

static MYSQL_SYSVAR_STR(
  db,                                                          /* name       */
  audit_tripwire_db_value,                                     /* value      */
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,                   /* flags      */
  "DB of the table to watch for",                              /* comment    */
  NULL,                                                        /* check()    */
  NULL,                                                        /* update()   */
  NULL                                                         /* default    */
);

static MYSQL_SYSVAR_BOOL(
  panic_mode,                                                  /* name       */
  panic_mode_value,                                            /* value      */
  PLUGIN_VAR_RQCMDARG,                                         /* flags      */
  "Table to watch for",                                        /* comment    */
  NULL,                                                        /* check()    */
  NULL,                                                        /* update()   */
  FALSE                                                        /* default    */
);



static struct st_mysql_sys_var* system_variables[] = {
  MYSQL_SYSVAR(db),
  MYSQL_SYSVAR(table),
  MYSQL_SYSVAR(panic_mode),
  NULL
};


static int audit_tripwire_init(MYSQL_PLUGIN p)
{
  plugin= p;
  return 0;
}

/** Plugin declaration */

mysql_declare_plugin(audit_tripwire)
{
  MYSQL_AUDIT_PLUGIN,                 /* type                            */
  &audit_tripwire_descriptor,         /* descriptor                      */
  "audit_tripwire",                   /* name                            */
  "Oracle Corp",                      /* author                          */
  "Tripwire service",                 /* description                     */
  PLUGIN_LICENSE_GPL,
  audit_tripwire_init,                /* init function (when loaded)     */
  NULL,                               /* deinit function (when unloaded) */
  0x0001,                             /* version                         */
  NULL,                               /* status variables                */
  system_variables,                   /* system variables                */
  NULL,
  0,
}
mysql_declare_plugin_end;
