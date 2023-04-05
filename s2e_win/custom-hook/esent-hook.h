#pragma once
#include <esent.h>

JET_ERR JET_API JetSetSystemParameterHook(
    JET_INSTANCE* pinstance,
    JET_SESID sesid,
    unsigned long paramid,
    JET_API_PTR lParam,
    JET_PCSTR szParam
);