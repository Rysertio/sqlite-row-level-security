#include <sqlite3.h>
#include <string.h>

static int row_filter(void* data, int argc, char** argv, char** col_names) {
    const char* role = (const char*)data;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(col_names[i], "role") == 0) {
            if (strcmp(argv[i], role) == 0) {
                return 1;  // Allow access
            }
        }
    }
    
    return 0;  // Deny access
}

static int row_access(void* data, int action_code, const char* arg1, const char* arg2, const char* dbName, const char* triggerName) {
    if (action_code == SQLITE_READ) {
        return SQLITE_OK;  // Allow read access
    }
    if (action_code == SQLITE_DELETE) {
        return SQLITE_OK;  // Allow delete access
    }
    return SQLITE_DENY;  // Deny other actions
}

int sqlite3_row_security_init(sqlite3 *db, char *zErrMsg, const sqlite3_api_routines *pApi) {
    int rc = SQLITE_OK;
    SQLITE_EXTENSION_INIT2(pApi);
    
    rc = sqlite3_create_function_v2(db, "row_filter", 3, SQLITE_UTF8 | SQLITE_DETERMINISTIC, "my_data", row_filter, 0, 0, 0);
    
    if (rc != SQLITE_OK) return rc;
    
    rc = sqlite3_set_authorizer(db, SQLITE_ACCESS, row_access, "my_data");
    
    return rc;
}
