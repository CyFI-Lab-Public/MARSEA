#include "esent-hook.h"
#include "utils.h"

JET_ERR JET_API JetSetSystemParameterHook(
    JET_INSTANCE* pinstance,
    JET_SESID sesid,
    unsigned long paramid,
    JET_API_PTR lParam,
    JET_PCSTR szParam
) {
    Message("[W] JetSetSystemParameter\n");
    return JetSetSystemParameter(pinstance, sesid, paramid, lParam, szParam);
}