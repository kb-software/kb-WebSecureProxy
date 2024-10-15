#ifndef _HOB_XS_TRANSLATOR_H
#define _HOB_XS_TRANSLATOR_H


#ifdef __cplusplus
     extern "C"
#endif
BOOL m_html5_to_rdp( struct dsd_browser_event*, struct dsd_rdp_user_event* );

#ifdef __cplusplus
     extern "C"
#endif
//BOOL m_rdp_to_html5( struct dsd_rdp_draw_command*, struct dsd_html5_answer* );
BOOL m_rdp_to_html5( struct dsd_rdp_draw_command*, struct dsd_rdp_event ** );



#endif