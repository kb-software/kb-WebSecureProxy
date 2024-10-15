#ifndef _AUTH_CALLBACK_H
#define _AUTH_CALLBACK_H

/*+-------------------------------------------------------------------------+*/
/*| calling modes:                                                          |*/
/*+-------------------------------------------------------------------------+*/
#define DEF_AUTH_CB_PARSE_LANG  0       // parse language name and get key
#define DEF_AUTH_CB_GET_LANG    1       // get language name by key

/*+-------------------------------------------------------------------------+*/
/*| calling structures:                                                     |*/
/*+-------------------------------------------------------------------------+*/
struct dsd_acb_language {
    const char*   achc_lang;              // language name
    int     inc_len_lang;           // length of lang name
    int     inc_key;                // language key
};

/*+-------------------------------------------------------------------------+*/
/*| functions:                                                              |*/
/*+-------------------------------------------------------------------------+*/
int m_auth_callback( void* av_session, int in_mode, void* av_param, int in_param_len );

#endif //_AUTH_CALLBACK_H
