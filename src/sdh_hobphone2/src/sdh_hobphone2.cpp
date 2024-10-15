/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   sdh_hobphone2                                                     |*/
/*|   2nd implementation of a server data hook for the HOBPhone         |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|   Heino Stömmer 2010/03                                             |*/
/*|                                                                     |*/
/*| Version:                                                            |*/
/*| ========                                                            |*/
/*|   0.1                                                               |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ==========                                                          |*/
/*|   HOB GmbH 2010                                                     |*/
/*|                                                                     |*/ 
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/
#define DEF_HL_INCL_INET
#ifdef HL_UNIX
    #include <netinet/in.h>
#else // windows
    #include <winsock2.h>
    #include <Ws2tcpip.h>
#include <windows.h>
#endif //HL_UNIX
#include <ds_wsp_helper.h>
#include "sdh_hobphone2.h"
#include "./config/ds_config.h"
#include "ds_hobphone2.h"
#include <limits.h>

/**
* function m_hlclib_conf
*  read our configuration from xml file
*
* @param[in]   struct dsd_hl_clib_dom_conf*    ads_conf
* @return      BOOL                                        TRUE = success
*/
extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf* ads_conf )
	{
#ifdef _DEBUG
	// check incoming parameter:
	if ( ads_conf == NULL ) {
		printf( SDH_ERROR(1), "ads_conf == NULL\n" );
		return FALSE;
		}
#endif
	// initialize some variables:
	BOOL          bo_ret;
	ds_wsp_helper dsc_wsp_helper;
	ds_config     dsc_config( &dsc_wsp_helper );
	dsc_wsp_helper.m_init_conf( ads_conf );
	//-----------------------------------------
	// print startup message:
	//-----------------------------------------
	dsc_wsp_helper.m_cb_printf_out( "HPHONEI%03dI %s V%s initialized",
		0, SDH_LONGNAME, SDH_VERSION_STRING );
	//-----------------------------------------
	// read and save configuration section:
	//-----------------------------------------
	bo_ret = dsc_config.m_read_config();
	if ( bo_ret == FALSE ) {
		dsc_wsp_helper.m_cb_printf_out( SDH_ERROR(6),
			"error while reading config - HOBPhone disabled" );
            return FALSE;
		}
	bo_ret = dsc_config.m_save_config();
	return (bo_ret == TRUE) ? TRUE : FALSE;
	} // end of m_hlclib_conf

//#define SDH_RELOAD_WAIT_SEC 60
#ifndef DEF_HL_INCL_INET
struct dsd_aux_get_session_info {           /* get information about the session */
   int        imc_session_no;               /* session number          */
   enum ied_conn_type_def iec_coty;         /* connection type         */
   enum ied_scp_def iec_scp_def;            /* server-conf protocol    */
   struct dsd_unicode_string dsc_scp_name;  /* server-conf protocol, only if ied_scp_spec */
   struct sockaddr_storage dsc_soa_client;  /* address information client */
   struct sockaddr_storage dsc_soa_server_this;  /* address information server on this side */
   struct sockaddr_storage dsc_soa_server_other;  /* address information server on other side */
   enum ied_aux_server_status iec_ass;      /* status about the server connection */
   enum ied_aux_server_type_co iec_ast;     /* type of connection to the server */
   BOOL       boc_csssl;                    /* with client-side SSL    */
// 30.07.10 KB missing L2TP / HTCP ...
   int        imc_server_port;              /* port of the server      */
   struct dsd_bind_ineta_1 *adsc_bind_out;  /* IP address multihomed   */
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* INETAs of the server */
};
#endif
 
void m_close_session(class  ds_wsp_helper* dsp_wsp_helper,class  ds_hobphone2* ads_hobphone,struct dsd_hl_clib_1* ads_trans)
{
    // check our class pointer
	if ( ads_hobphone == NULL ) {
		dsp_wsp_helper->m_cb_printf_out( SDH_WARN(19), "session pointer is null" );
		return;
		}
	// log end of connection:
	dsp_wsp_helper->m_log_output();
	// setup storage container:
	dsp_wsp_helper->m_use_storage( &(ads_hobphone->av_storage), SDH_STORAGE_SIZE );
	// init main working class:
	ads_hobphone->m_init( dsp_wsp_helper );
	// call destructor for our working class:
	ads_hobphone->ds_hobphone2::~ds_hobphone2();
	// clear storage container:
	dsp_wsp_helper->m_no_storage( &(ads_hobphone->av_storage) );
	// free working class memory:
	dsp_wsp_helper->m_cb_free_memory( (char*)ads_trans->ac_ext, sizeof(ds_hobphone2) );
}
/**
* function m_hlclib01
*  working function
*
* @param[in]   struct dsd_hl_clib1*    ads_trans
*/
extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1* ads_trans )
	{
#ifdef _DEBUG
	// check incoming parameter:
	if ( ads_trans == NULL ) {
		printf( SDH_ERROR(2), "ads_trans == NULL\n");
		return;
		}
#endif

	// initialize some variables:
	int                   iml_ret;
#ifdef _DEBUG
	int                    in_locks;
#endif // _DEBUG
	class  ds_wsp_helper dsc_wsp_helper;
	class  ds_hobphone2* ads_hobphone = (ds_hobphone2*)ads_trans->ac_ext;
	struct dsd_sdh_config* ads_config  = (dsd_sdh_config_t*)ads_trans->ac_conf;
	dsc_wsp_helper.m_init_trans( ads_trans );

	if ( ads_config == NULL ) {
		dsc_wsp_helper.m_cb_printf_out( SDH_ERROR(8), "config pointer == NULL" );
		dsc_wsp_helper.m_return_error();
		return;
		}

	switch ( ads_trans->inc_func ) {

		//-----------------------------------------
		// start session:
		//-----------------------------------------
		case DEF_IFUNC_START:
            {

            //BOOL bol_rc;
            //struct dsd_aux_get_session_info dsl_sessioninfo;
            //memset( &dsl_sessioninfo, 0, sizeof(struct dsd_aux_get_session_info) );
            //bol_rc = ads_trans->amc_aux( ads_trans->vpc_userfld,
            //                        DEF_AUX_GET_SESSION_INFO,  /* get information about the session */
            //                        &dsl_sessioninfo,  /* get information about the session */
            //                        sizeof(struct dsd_aux_get_session_info) );

            

            //
            //memset(&dsl_amsr,0,sizeof(dsd_hl_aux_manage_sdh_reload));
            //
            //dsl_amsr.achc_addr_sdh_name = chrl_name;  /* address of SDH name   */
            //dsl_amsr.imc_len_sdh_name = 15 ;   /* length of SDH name      */
            //dsl_amsr.imc_wait_seconds = SDH_RELOAD_WAIT_SEC;  /* wait seconds for destroy */
            //dsl_amsr.iec_asrc = ied_asrc_define;     /* define this SDH for reload */
            //bol_rc = ads_trans->amc_aux( ads_trans->vpc_userfld,
            //                    DEF_AUX_SDH_RELOAD,  /* manage SDH reload */
            //                    &dsl_amsr,
            //                    sizeof(struct dsd_hl_aux_manage_sdh_reload) );

            // get memory for our working class
			// and put in ac_ext pointer -> we will get it again on every call
			ads_trans->ac_ext = dsc_wsp_helper.m_cb_get_memory( sizeof(ds_hobphone2), TRUE );
			if ( ads_trans->ac_ext == NULL ) {
				dsc_wsp_helper.m_cb_printf_out( SDH_ERROR(3), "cannot get session memory" );
				dsc_wsp_helper.m_return_error();
				return;
				}

			// setup our main working class:
			ads_hobphone = new(ads_trans->ac_ext) ds_hobphone2();

			// init main working class:
			ads_hobphone->m_init( &dsc_wsp_helper );

            //start the initial timeout
            if (ads_config->im_tcp_keepalive > 0)
                BOOL bol_ret = ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_TIMER1_SET, NULL, (ads_config->im_tcp_keepalive)+2000);
            
            struct dsd_timer1_ret dsl_tr;
            BOOL bol_ret = ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_TIMER1_QUERY, &dsl_tr, sizeof(dsl_tr));

			// setup storage container:
			dsc_wsp_helper.m_use_storage( &(ads_hobphone->av_storage), SDH_STORAGE_SIZE );



			// log start of connection:
			dsc_wsp_helper.m_log_input();
            }
			break;

			//-----------------------------------------
			// end session:
			//-----------------------------------------
		case DEF_IFUNC_CLOSE:
#if DEBUG_RECONNECT
            dsc_wsp_helper.m_cb_printf_out( "SDH RELOAD - DEF_IFUNC_CLOSE session %d",ads_trans->imc_sno );
#endif
            m_close_session(&dsc_wsp_helper,ads_hobphone,ads_trans);
#if DEBUG_RECONNECT
			dsc_wsp_helper.m_cb_printf_out( "SDH RELOAD - DEF_IFUNC_CLOSE done session %d",ads_trans->imc_sno );
#endif
			break;

			//-----------------------------------------
			// working session modes:
			//-----------------------------------------
        case DEF_IFUNC_TOSERVER:
		case DEF_IFUNC_CONT:
		case DEF_IFUNC_FROMSERVER:		
		case DEF_IFUNC_REFLECT:
			
			// check our class pointer
			if ( ads_hobphone == NULL ) {
				dsc_wsp_helper.m_cb_printf_out( SDH_WARN(20), "session pointer is null" );
				dsc_wsp_helper.m_return_close();
				return;
				}
			// setup storage container:
			dsc_wsp_helper.m_use_storage( &(ads_hobphone->av_storage), SDH_STORAGE_SIZE );
			// init main working class:
			ads_hobphone->m_init( &dsc_wsp_helper );

			// log input data:
			dsc_wsp_helper.m_log_input();

            ads_hobphone->m_set_aux(ads_trans->amc_aux,ads_trans->vpc_userfld);
			iml_ret = ads_hobphone->m_run();               
            if (iml_ret == SDH_HOBPHONE_RUNSTATE_SAVESDH)
            {
                //save SDH
                 //
                if (ads_config->im_reload_timeout > 0)
                {
                    char chrl_work[RELOAD_NAME_MAXLEN+1] = {0};
                    memcpy(chrl_work,(void*)"HOBPhone ",9);

                    dsd_sdh_ident_set_1 ds_ident;
                    dsc_wsp_helper.m_cb_get_ident(&ds_ident);

                    int iml_idlen = ds_ident.dsc_userid.imc_len_str;
                    if (iml_idlen + 9 >= RELOAD_NAME_MAXLEN)
                    {            
                        //truncate to avoid writing beyond buffer range BUT 
                        //log as an error since this can cause other problems 
                        //(if we trucante the id there might be other users with the same id)
                        dsc_wsp_helper.m_log(ied_sdh_log_error, "Unexpected userid length - truncating");
                        iml_idlen = RELOAD_NAME_MAXLEN-9;

                    }
                    memcpy(&(chrl_work[9]),ds_ident.dsc_userid.ac_str,iml_idlen);
                    int iml_currlen = 9 + iml_idlen;

#if !NO_DEVID
                    const char* achr_devid;
                    int iml_devidlen = ads_hobphone->m_getdevid(&achr_devid);
                    if (iml_devidlen + iml_currlen > RELOAD_NAME_MAXLEN)
                    {
                        //truncate to avoid writing beyond buffer range BUT 
                        //log as an error since this can cause other problems 
                        //(if we trucante the id there might be other users with the same id)
                        dsc_wsp_helper.m_log(ied_sdh_log_error, "Unexpected device name length - truncating");
                        iml_devidlen = RELOAD_NAME_MAXLEN - iml_currlen;
                    }
                    memcpy(&(chrl_work[iml_currlen]),achr_devid,iml_devidlen);
                    iml_currlen += iml_devidlen;
#endif               

                    
                    struct dsd_hl_aux_manage_sdh_reload dsl_amsr;

                    memset(&dsl_amsr,0,sizeof(dsd_hl_aux_manage_sdh_reload));
                    
                    dsl_amsr.achc_addr_sdh_name = chrl_work;  /* address of SDH name   */
                    dsl_amsr.imc_len_sdh_name = iml_currlen ;   /* length of SDH name      */
                    dsl_amsr.imc_wait_seconds = ads_config->im_reload_timeout;  /* wait seconds for destroy */
                    dsl_amsr.iec_asrc = ied_asrc_define;     /* define this SDH for reload */
                    BOOL bol_rc = ads_trans->amc_aux( ads_trans->vpc_userfld,
                                        DEF_AUX_SDH_RELOAD,  /* manage SDH reload */
                                        &dsl_amsr,
                                        sizeof(struct dsd_hl_aux_manage_sdh_reload) );

#if DEBUG_RECONNECT
                    if (bol_rc && dsl_amsr.iec_asrr == ied_asrr_ok)
                    {
                        dsc_wsp_helper.m_cb_printf_out( "SDH RELOAD - SDH saved, hobphone:%x",ads_hobphone);                    
                    }
                    else 
                    {
                        dsc_wsp_helper.m_cb_printf_out( "SDH RELOAD - SDH save failed, hobphone:%x",ads_hobphone);
                    }
#endif

                }


            }
            else if (iml_ret == SDH_HOBPHONE_RUNSTATE_RELOAD || iml_ret == SDH_HOBPHONE_RUNSTATE_RELOAD2)
            {
                //client reconnected 
#if DEBUG_RECONNECT
                dsc_wsp_helper.m_cb_printf_out( "SDH RELOAD - SDH_HOBPHONE_RUNSTATE_RELOAD session %d",ads_trans->imc_sno );
#endif
                char chrl_work[RELOAD_NAME_MAXLEN+1] = {0};
                memcpy(chrl_work,(void*)"HOBPhone ",9);

                dsd_sdh_ident_set_1 ds_ident;
                dsc_wsp_helper.m_cb_get_ident(&ds_ident);

                int iml_idlen = ds_ident.dsc_userid.imc_len_str;
                if (iml_idlen + 9 >= RELOAD_NAME_MAXLEN)
                {            
                    //truncate to avoid writing beyond buffer range BUT 
                    //log as an error since this can cause other problems 
                    //(if we trucante the id there might be other users with the same id)
                    dsc_wsp_helper.m_log(ied_sdh_log_error, "Unexpected userid length - truncating");
                    iml_idlen = RELOAD_NAME_MAXLEN-9;

                }
                memcpy(&(chrl_work[9]),ds_ident.dsc_userid.ac_str,iml_idlen);
                int iml_currlen = 9 + iml_idlen;

#if !NO_DEVID
                const char* achr_devid;
                int iml_devidlen = ads_hobphone->m_getdevid(&achr_devid);
                if (iml_devidlen + iml_currlen > RELOAD_NAME_MAXLEN)
                {
                    //truncate to avoid writing beyond buffer range BUT 
                    //log as an error since this can cause other problems 
                    //(if we trucante the id there might be other users with the same id)
                    dsc_wsp_helper.m_log(ied_sdh_log_error, "Unexpected device name length - truncating");
                    iml_devidlen = RELOAD_NAME_MAXLEN - iml_currlen;
                }
                memcpy(&(chrl_work[iml_currlen]),achr_devid,iml_devidlen);
                iml_currlen += iml_devidlen;
#endif               
                
                struct dsd_hl_aux_manage_sdh_reload dsl_amsr;

                memset( &dsl_amsr, 0, sizeof(struct dsd_hl_aux_manage_sdh_reload) );  /* manage SDH reload */
                dsl_amsr.achc_addr_sdh_name = chrl_work;  /* address of SDH name   */
                dsl_amsr.imc_len_sdh_name = iml_currlen;   /* length of SDH name      */
                dsl_amsr.imc_wait_seconds = ads_config->im_tcp_keepalive;  /* wait seconds for destroy */
                dsl_amsr.iec_asrc = ied_asrc_reload;     /* reload saved SDH        */
                BOOL bol_rc = ads_trans->amc_aux( ads_trans->vpc_userfld,
                                        DEF_AUX_SDH_RELOAD,  /* manage SDH reload */
                                        &dsl_amsr,
                                        sizeof(struct dsd_hl_aux_manage_sdh_reload) );

                 if (dsl_amsr.iec_asrr == ied_asrr_ok)
                 {
                    BOOL bol_send = dsc_wsp_helper.m_send_data(ds_hobphone2::astr_reload_response_ok, strlen(ds_hobphone2::astr_reload_response_ok));
                    m_close_session(&dsc_wsp_helper,ads_hobphone,ads_trans);
#if DEBUG_RECONNECT
                    dsc_wsp_helper.m_cb_printf_out( "SDH RELOAD - session found, will reload, hobphone:%x",ads_hobphone);                          
#endif
                 }
                 else
                 {
                    BOOL bol_send = dsc_wsp_helper.m_send_data(ds_hobphone2::astr_reload_response_fail, strlen(ds_hobphone2::astr_reload_response_fail));
#if DEBUG_RECONNECT
                    dsc_wsp_helper.m_cb_printf_out( "SDH RELOAD - session not found - new session established, hobphone:%x",ads_hobphone );
#endif
                 }

                 break;
            }
            else if (iml_ret == SDH_HOBPHONE_RUNSTATE_SHUTDOWN)
            {
#if DEBUG_RECONNECT
                dsc_wsp_helper.m_cb_printf_out( "SDH RELOAD - SHUTDOWN ending session, hobphone:%x",ads_hobphone );
#endif
                m_close_session(&dsc_wsp_helper,ads_hobphone,ads_trans);
                ads_trans->inc_return = DEF_IRET_END;                
            }
            else if (iml_ret == SDH_HOBPHONE_RUNSTATE_OK)
            {
                //on shutdown ads_hobphone is no longer valid
                //on reload it is not needed since there will always be some other data
                ads_hobphone->m_check_timeout(ads_trans, TRUE );      
            }
            else if (iml_ret == SDH_HOBPHONE_RUNSTATE_OK_NODATA)
            {                                                  
                ads_hobphone->m_check_timeout(ads_trans, FALSE);      
            }

			// log output data:
			dsc_wsp_helper.m_log_output();

			if ( iml_ret < 0) {
				dsc_wsp_helper.m_cb_printf_out( SDH_WARN(21), "working class returned false" );
			}
            
			break;       
        case DEF_IFUNC_CLIENT_DISCO:
#if DEBUG_RECONNECT
            dsc_wsp_helper.m_cb_printf_out("SDH RELOAD - DEF_IFUNC_CLIENT_DISCO session %d",ads_trans->imc_sno );
#endif
            ads_hobphone->m_client_disco();
            break;
        case DEF_IFUNC_RELOAD:
#if DEBUG_RECONNECT
            dsc_wsp_helper.m_cb_printf_out( "SDH RELOAD - DEF_IFUNC_RELOAD session %d",ads_trans->imc_sno );
#endif
            ads_hobphone->m_reloaded();            
            break;
        case DEF_IFUNC_PREP_CLOSE:
#if DEBUG_RECONNECT
            dsc_wsp_helper.m_cb_printf_out( "SDH RELOAD - PREP_CLOSE, hobphone:%x session %d",ads_hobphone,ads_trans->imc_sno );
#endif
            break;
        //-----------------------------------------
        // unknown session modes:
        //-----------------------------------------
		default:
            dsc_wsp_helper.m_cb_printf_out( "unsupported inc_func selected. hobphone:%p",ads_hobphone );
			dsc_wsp_helper.m_return_close();
			break;

		} // end of switch ( ads_trans->inc_func )

    

#ifdef _DEBUG
	in_locks = dsc_wsp_helper.m_count_cma_lock();
	if ( in_locks > 0 ) {
		dsc_wsp_helper.m_cb_printf_out( "Number of CMA-LOCKS = %d\n", in_locks );
		dsd_unicode_string* ads_crash = NULL;
		ads_crash->ac_str = NULL;
		}
#endif

	return;
	} // end of m_hlclib01


    


