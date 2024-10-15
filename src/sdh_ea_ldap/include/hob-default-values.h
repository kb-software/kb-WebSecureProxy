//////////////////////////////////////////////////////////////////////
//
// Filename       :    hob-default-values.h
//
// Description    :    Header file which holds default values (e.g. used in PNode).
//
// Date           :    09.07.2009
//
// Author         :    Joachim Frank HOB GmbH & Co. KG
//
///////////////////////////////////////////////////////////////////////

#ifndef __HOB_DEFAULT_VALUES_H__
#define __HOB_DEFAULT_VALUES_H__

#define HOB_DEF_GENERIC_CMD    -1
#define HOB_DEF_WRITE_MODE      0

#define HOB_VERIFY_PWD          0       // verify whether item exists + password checking
#define HOB_VERIFY_NOPWD        1       // verify whether item exists; no password checking
#define HOB_DEF_VERIFY          HOB_VERIFY_PWD
#define HOB_RET_VERIFY_OK                0
#define HOB_RET_VERIFY_NOT_FOUND    0x7012
#define HOB_RET_VERIFY_INVALID_PW   0x7014

#define HOB_DEF_TYPE_S         "u"
#define HOB_DEF_TYPE_C         'u'

#define HOB_DEF_USER           "guest"

#define HOB_DEF_BINARY         false

#endif  // #ifndef __HOB_DEFAULT_VALUES_H__
