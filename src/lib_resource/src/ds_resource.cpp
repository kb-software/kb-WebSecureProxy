/*+-------------------------------------------------------------------------+*/
/*| include headers                                                         |*/
/*+-------------------------------------------------------------------------+*/
#ifdef HL_UNIX
    #include <hob-unix01.h>
#else // windows
    #include <windows.h>
#endif //HL_UNIX
#include <stddef.h>
#include <limits.h>

#ifndef _HOB_AVL03_H
    #define _HOB_AVL03_H
    #include <hob-avl03.h>
#endif //_HOB_AVL03_H

#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H

#include <ds_wsp_helper.h>
#include <ds_xml.h>
#include "ds_resource.h"

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#define DEF_FIRST_TAG   "languages"

/*+-------------------------------------------------------------------------+*/
/*| avl content structure:                                                  |*/
/*+-------------------------------------------------------------------------+*/
struct dsd_language_sort {
   struct dsd_htree1_avl_entry dsc_sort;        // entry for sorting
   int                         in_language;     // key for language
   char*                       ach_lang;        // name for language
   int                         in_len_lang;     // length of name for language
   struct dsd_htree1_avl_cntl  ds_avl_control;  // language avltree control structure
};

struct dsd_resource_sort {
   struct dsd_htree1_avl_entry dsc_sort;        // entry for sorting
   unsigned int                uin_hash;        // hash of key
   const char*                 ach_key;         // key of entry
   int                         in_len_key;      // length of key
   const char*                 ach_value;       // value of entry
   int                         in_len_value;    // length of value
};

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/
ds_resource::ds_resource(void)
{
    in_no_lang     = 0;
}

/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/
ds_resource::~ds_resource(void)
{
}

/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/**
 * function ds_resource::m_setup
 *
 * @param[in]		ds_wsp_helper*						adsl_wsp_helper     wsp helper class
 * @param[in]		const char*							ach_file            resource filename
 * @param[in]		int									in_len_file         length of filename
 * @param[in/out]	struct dsd_aux_get_workarea *		adsp_workarea		place to store resources
 * @return			bool                                true = success
*/
bool ds_resource::m_setup( ds_wsp_helper* adsl_wsp_helper,
                           const char* ach_file, int in_len_file,
						   struct dsd_aux_get_workarea* adsp_workarea )
{
    // initialize some variables:
    bool         bo_ret;
    ds_xml       dsc_xml;
    dsd_xml_tag* ads_xml;
    dsd_xml_tag* ads_lang;

    //----------------------------------------
    // init global class variables:
    //----------------------------------------
    dsc_xml.m_init( adsl_wsp_helper );

	struct dsd_hl_aux_diskfile_1 dsl_read_diskfile;
    //----------------------------------------
    // read file:
    //----------------------------------------
    bo_ret = m_read_file( adsl_wsp_helper, ach_file, in_len_file, &dsl_read_diskfile, &dsc_xml );
    if ( bo_ret == false ) {
        adsl_wsp_helper->m_cb_printf_out("HIWSE084E: m_read_file failed (file %.*s).", in_len_file, ach_file);        
        return false;
    }
    ads_xml		= dsc_xml.m_get_firstnode( );

    const char* achl_lang;
	int inl_len;
	dsc_xml.m_get_node_name( ads_xml, &achl_lang, &inl_len );

	ads_lang	= dsc_xml.m_get_firstchild( ads_xml );
    //----------------------------------------
    // init main avl tree:
    //----------------------------------------
    bo_ret = m_init_avl();
    if ( bo_ret == false ){
        adsl_wsp_helper->m_cb_printf_out("HIWSE084E: m_init_avl failed.");        
        goto LBL_ERROR;
    }
    
    //----------------------------------------
    // get all supported languages:
    //----------------------------------------
    // ads_lang = ds_xml::m_get_firstchild( ads_xml );
    while ( ads_lang != NULL )
	{
        //------------------------------------
        // insert language:
        //------------------------------------
        bo_ret = m_insert_lang( adsl_wsp_helper, ads_lang, adsp_workarea );
        if ( bo_ret == false ) {
            adsl_wsp_helper->m_cb_printf_out("HIWSE084E: m_insert_lang failed.");        
            goto LBL_ERROR;
        }

        //------------------------------------
        // get next language:
        //------------------------------------
        ads_lang = dsc_xml.m_get_nextsibling( ads_lang );
    }

	adsl_wsp_helper->m_cb_file_release( &dsl_read_diskfile );
    return true;
LBL_ERROR:
	adsl_wsp_helper->m_cb_file_release( &dsl_read_diskfile );
    return false;
} // end of ds_resource::m_setup


/**
 * function ds_resource::m_get
 * get resource for a key in selected language
 *
 * @param[in]   int         in_lang             select language
 * @param[in]   const char* ach_key             resource key
 * @param[in]   int         in_len_key          length of key
 * @param[out]  char**      aach_res            pointer to resource
 * @param[out]  int*        ain_len             length of resource
 * @return      bool                            true = success
 *                                              false is returned:
 *                                              -> wrong input data
 *                                              -> no languages at all found
 *                                              -> selected language not found, even if default resource returned
*/
bool ds_resource::m_get( int in_lang,
                         const char* ach_key, int in_len_key,
                         const char** aach_res, int* ain_len        ) const
{
    // initialize some variables:
    dsd_language_sort*  ads_lang;           // found language structure
    dsd_resource_sort*  ads_res;            // found resource structure

    
    //----------------------------------------
    // check input:
    //----------------------------------------
    if (    ach_key == NULL     /* invalid key            */
         || in_len_key < 1      /* invalid key lenght     */
         || in_no_lang == 0     /* no languages available */ ) {
        return false;
    }
    if ( in_lang < 0 || in_lang > in_no_lang ) {
        in_lang = 0;    // select default language
    }


    //----------------------------------------
    // search for language:
    //----------------------------------------
    ads_lang = (dsd_language_sort*)m_search_lang( in_lang );
    if ( ads_lang == NULL ) {
        /*
            should never happen:
            -> if in_lang outside valid range, we have selected default lang
            -> only possibility is that there are no resources at all
        */
        *aach_res = (char*)"selected language not found";
        *ain_len  = (int)strlen("selected language not found");
        return false;
    }
    
    //----------------------------------------
    // search for key:
    //----------------------------------------
    ads_res = (dsd_resource_sort*)m_search_res( &ads_lang->ds_avl_control, ach_key, in_len_key );
    if ( ads_res == NULL ) {
        /*
            selected resource for this language not found
            -> if default language is selected, return error message
            -> if specific language is selected, try to get default message
        */
        if ( in_lang == 0 ) {
            *aach_res = (char*)"selected resource not found";
            *ain_len  = (int)strlen("selected resource not found");
        } else {
            m_get( 0, ach_key, in_len_key, aach_res, ain_len );
        }
        return false;
    }

    *aach_res = (char*)ads_res->ach_value;
    *ain_len  = ads_res->in_len_value;
    return true;
} // end of ds_resource::m_get


/**
 * function ds_resource::m_get
 * get resource for a key in selected language
 *
 * @param[in]   int         in_lang             select language
 * @param[in]   const char* ach_key             resource key (zero terminated!)
 * @param[out]  char**      aach_res            pointer to resource
 * @param[out]  int*        ain_len             length of resource
 * @return      bool                            true = success
*/
bool ds_resource::m_get( int in_lang, const char* ach_key,
                         const char** aach_res, int* ain_len ) const
{
    if ( ach_key != NULL ) {
        return m_get( in_lang, ach_key, (int)strlen(ach_key), aach_res, ain_len );
    }
    return false;
} // end of ds_resource::m_get


/**
 * function ds_resource::m_count_lang
 * count number of supported languages
 *
 * @return      int
*/
int ds_resource::m_count_lang() const
{
    return in_no_lang;
} // end of ds_resource::m_count_lang


/**
 * function ds_resource::m_parse_lang
 * parse lang string and give an type back
 *
 * @param[in]   const char* ach_lang
 * @param[in]   int         in_len
 * @return      int
*/
int ds_resource::m_parse_lang( const char* ach_lang, int in_len ) const
{
    // initialize some variables:
    dsd_language_sort*  ads_lang;           // found language structure
    int                 in_index;
    int                 in_comp;

    for ( in_index = 0; in_index < in_no_lang; in_index++ ) {
        ads_lang = (dsd_language_sort*)m_search_lang( in_index );
        if ( ads_lang != NULL ) {
            in_comp = in_len;
            if ( in_len > ads_lang->in_len_lang ) {
                in_comp = ads_lang->in_len_lang;
            }
            if ( memcmp( ads_lang->ach_lang, ach_lang, in_comp ) == 0 ) {
                return in_index;
            }
        } else {
            return -1;
        }
    }
    return -1;
} // end of ds_resource::m_parse_lang


/**
 * function ds_resource::m_get_lang
 * get name of lang tag
 *
 * @param[in]   int         in_lang
 * @param[out]  char**      aach_lang
 * @param[out]  int*        ain_len
 * @return      bool
*/
bool ds_resource::m_get_lang( int in_lang, const char** aach_lang, int* ain_len ) const
{
    // initialize some variables:
    dsd_language_sort*  ads_lang;           // found language structure

    ads_lang = (dsd_language_sort*)m_search_lang( in_lang );
    if ( ads_lang != NULL ) {
        *aach_lang = ads_lang->ach_lang;
        *ain_len   = ads_lang->in_len_lang;
        return true;
    }
    return false;
} // end of ds_resource::m_get_lang


/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/
/**
 * function ds_resource::m_init_avl
 * init language main avl tree
 *
 * @return      bool                                    true = success
*/
bool ds_resource::m_init_avl()
{
    BOOL bo_ret = m_htree1_avl_init( NULL, &ds_avl_control,
                                     &m_avl_lang_compare );
    return (bo_ret)?true:false;
} // end of ds_resource::m_init_avl


/**
 * function ds_resource::m_search_lang
 * search language inside avl tree
 *
 * @param[in]   int     in_key
 * @return      void*           pointer to found dsd_language_sort structure  
*/
void* ds_resource::m_search_lang( int in_key ) const
{
    // initialize some variables:
    BOOL                bo_ret;                 // return value for avl calls
    dsd_htree1_avl_work ds_avl_work;            // avl working structure
    dsd_language_sort   ds_lang_sort;           // search language structure

    ds_lang_sort.in_language = in_key;
    bo_ret = m_htree1_avl_search( NULL,
                                  const_cast <dsd_htree1_avl_cntl*> (&ds_avl_control),
                                  &ds_avl_work,
                                  &ds_lang_sort.dsc_sort );
    if ( bo_ret == FALSE || ds_avl_work.adsc_found == NULL ) {
        return NULL;
    }
    return ((char *) ds_avl_work.adsc_found - offsetof( dsd_language_sort, dsc_sort ));
} // end of ds_resource::m_search_lang


/**
 * function ds_resource::m_search_res
 * search resource inside avl tree
 *
 * @param[in]   dsd_htree1_avl_cntl*    ads_avl_cntl    current avl tree control
 * @param[in]   const char*             ach_key         resource key
 * @param[in]   int                     in_len_key      length of key
 * @return      void*                                   pointer to found dsd_resource_sort structure  
*/
void* ds_resource::m_search_res( dsd_htree1_avl_cntl* ads_avl_cntl,
                                 const char* ach_key, int in_len_key ) const
{
    // initialize some variables:
    BOOL                bo_ret;                 // return value for avl calls
    dsd_htree1_avl_work ds_avl_work;            // avl working structure
    dsd_resource_sort   ds_res_sort;            // search resource structure

    ds_res_sort.ach_key    = ach_key;
    ds_res_sort.in_len_key = in_len_key;
    ds_res_sort.uin_hash   = m_get_hash( ach_key, in_len_key );
    bo_ret = m_htree1_avl_search( NULL,
                                  ads_avl_cntl,
                                  &ds_avl_work,
                                  &ds_res_sort.dsc_sort );
    if ( bo_ret == FALSE || ds_avl_work.adsc_found == NULL ) {
        return NULL;
    }
    return ((char *) ds_avl_work.adsc_found - offsetof( dsd_resource_sort, dsc_sort ));
} // end of ds_resource::m_search_res

/**
 * function ds_resource::m_insert_lang
 * insert language inside avl tree
 *
 * @param[in]   ds_wsp_helper*  adsl_wsp_helper
 * @param[in]   dsd_xml_tag*    ads_lang
 * @return      bool                            true = success
*/
bool ds_resource::m_insert_lang( ds_wsp_helper* adsl_wsp_helper, dsd_xml_tag* ads_lang, struct dsd_aux_get_workarea* adsp_workarea )
{
    // initialize some variables:
    BOOL                bo_ret;                 // return value for avl calls
    dsd_htree1_avl_work ds_avl_work;            // avl working structure
    dsd_language_sort*  ads_lang_sort;          // insert structure
    ds_xml              dsc_xml;
	int					iml_size;

	//----------------------------------------
    // get memory for our insert structure
    // (must be global memory)
	// hofmants: stored data in wa instead of "evil" memory
    //----------------------------------------
	iml_size = (int)sizeof(dsd_language_sort);
	if( adsp_workarea->imc_len_work_area < iml_size )
	{
		bo_ret = adsl_wsp_helper->m_cb_get_persistent_workarea( adsp_workarea, iml_size );
		if( !bo_ret ){ return false; }
	}

	ads_lang_sort = (dsd_language_sort*) adsp_workarea->achc_work_area;
	adsp_workarea->imc_len_work_area -= iml_size;
	adsp_workarea->achc_work_area += iml_size;

	const char	*achl_lang;
    //----------------------------------------
    // fill resource structure:
    //----------------------------------------
    ads_lang_sort->in_language = in_no_lang;
    dsc_xml.m_get_node_name( ads_lang, &achl_lang, &ads_lang_sort->in_len_lang );
	memcpy( adsp_workarea->achc_work_area, achl_lang, ads_lang_sort->in_len_lang );
                             
	ads_lang_sort->ach_lang = adsp_workarea->achc_work_area;
    adsp_workarea->imc_len_work_area -= ads_lang_sort->in_len_lang;
	adsp_workarea->achc_work_area += ads_lang_sort->in_len_lang;

    bo_ret = m_htree1_avl_init( NULL,
                                &ads_lang_sort->ds_avl_control,
                                &m_avl_compare );

    //----------------------------------------
    // search if entry already exists:
    //----------------------------------------
    bo_ret = m_htree1_avl_search( NULL,
                                  &ds_avl_control,
                                  &ds_avl_work,
                                  &ads_lang_sort->dsc_sort );
    if ( bo_ret == FALSE || ds_avl_work.adsc_found != NULL ){ return false; }

    //----------------------------------------
    // insert main avl entry:
    //----------------------------------------
    bo_ret = m_htree1_avl_insert( NULL,
                                  &ds_avl_control,
                                  &ds_avl_work,
                                  &ads_lang_sort->dsc_sort );
    if ( bo_ret == FALSE ){ return false; }
    in_no_lang++;
    
    //----------------------------------------
    // insert resources for current lang:
    //----------------------------------------
    return m_insert_res( adsl_wsp_helper,
						 adsp_workarea,
                         &ads_lang_sort->ds_avl_control,
                         ds_xml::m_get_firstchild( ads_lang ) );
} // end of ds_resource::m_insert_lang


/**
 * function ds_resource::m_insert
 * insert key/value pair inside avl tree
 *
 * @param[in]   ds_wsp_helper*          adsl_wsp_helper wsp helper class
 * @param[in]   dsd_htree1_avl_cntl*    ads_avl_cntl    current avl tree control
 * @param[in]   dsd_xml_tag*            ads_res         resource xml tag
 * @param[in]   const char*             ach_prefix      prefix for key
 * @param[in]   int                     in_len_prefix   length of prefix
 * @return      bool                                    true = success
*/
bool ds_resource::m_insert_res( ds_wsp_helper* adsl_wsp_helper,
							    struct dsd_aux_get_workarea* adsp_workarea,
                                dsd_htree1_avl_cntl* ads_avl_cntl, dsd_xml_tag* ads_res,
                                const char* ach_prefix, int in_len_prefix )
{
    // initialize some variables:
    BOOL                bo_ret;                 // return value for avl calls
    dsd_htree1_avl_work ds_avl_work;            // avl working structure
    dsd_resource_sort*  ads_resource;           // insert structure
    const char*               ach_key;                // key
    int                 in_len_key;             // length of key
    const char*               ach_value;              // value
    int                 in_len_value;           // length of value
	char*				achl_temp;				// points to workarea where data starts

    //--------------------------------------------
    // get key:
    //--------------------------------------------
    ds_xml::m_get_node_name( ads_res, &ach_key, &in_len_key );
    if ( ach_key == NULL || in_len_key < 1 ){ return false; }

	/* save the start point of the wa */
	achl_temp = adsp_workarea->achc_work_area;

	/* first put the prefix in the workarea */
	if ( in_len_prefix > 0 )
	{
		/* check if there is enough space left in our persistent WA */
		int inl_len_needed = ( in_len_prefix + 1 + in_len_key );
		if( adsp_workarea->imc_len_work_area < inl_len_needed )
		{
			bo_ret = adsl_wsp_helper->m_cb_get_persistent_workarea( adsp_workarea, inl_len_needed );
			if( !bo_ret ){ return false; }
			achl_temp = adsp_workarea->achc_work_area;
		}
		
        memcpy( adsp_workarea->achc_work_area, ach_prefix, in_len_prefix );
        memcpy( adsp_workarea->achc_work_area + in_len_prefix, "/", 1 );

		/* reduce the available wa memory*/
		adsp_workarea->achc_work_area		+= in_len_prefix + 1;
		adsp_workarea->imc_len_work_area	-= in_len_prefix + 1;
    }
	else
	{
		if( adsp_workarea->imc_len_work_area < in_len_key )
		{
			bo_ret = adsl_wsp_helper->m_cb_get_persistent_workarea( adsp_workarea, in_len_key );
			if( !bo_ret ){ return false; }
			achl_temp = adsp_workarea->achc_work_area;
		}
	}

	/* now copy the actual key after the prefix */
	memcpy( adsp_workarea->achc_work_area, ach_key, in_len_key );
	adsp_workarea->achc_work_area		+= in_len_key;
	adsp_workarea->imc_len_work_area	-= in_len_key;

	/* get total length */
	if( in_len_prefix > 0 ){ in_len_key += in_len_prefix + 1; }
	ach_key = achl_temp;

    //--------------------------------------------
    // get value:
    //--------------------------------------------
    ds_xml::m_get_node_value( ads_res, &ach_value, &in_len_value );
    if ( ach_value != NULL && in_len_value > 0 )
	{

		if( adsp_workarea->imc_len_work_area < in_len_value )
		{
			bo_ret = adsl_wsp_helper->m_cb_get_persistent_workarea( adsp_workarea, in_len_value );
			if( !bo_ret ){ return false; }
		}

		memcpy( adsp_workarea->achc_work_area, ach_value, in_len_value );
		ach_value = adsp_workarea->achc_work_area;

		adsp_workarea->achc_work_area		+= in_len_value;
		adsp_workarea->imc_len_work_area	-= in_len_value;

        //----------------------------------------
        // get memory for our insert structure
        // (must be global memory)
		// hofmants: store stuff in persistent WA
        //----------------------------------------

		/* check if there is enough space left in our persistent WA */
		if( adsp_workarea->imc_len_work_area < (int)sizeof(dsd_resource_sort) )
		{
			bo_ret = adsl_wsp_helper->m_cb_get_persistent_workarea( adsp_workarea, (int)sizeof(dsd_resource_sort) );
			if( !bo_ret ){ return false; }
		}
		ads_resource = (dsd_resource_sort*)adsp_workarea->achc_work_area;
		adsp_workarea->achc_work_area		+= (int)sizeof(dsd_resource_sort);
		adsp_workarea->imc_len_work_area	-= (int)sizeof(dsd_resource_sort);

        //----------------------------------------
        // fill resource structure:
        //----------------------------------------
        ads_resource->ach_key      = ach_key;
        ads_resource->in_len_key   = in_len_key;
        ads_resource->ach_value    = ach_value;
        ads_resource->in_len_value = in_len_value;
        ads_resource->uin_hash     = m_get_hash( ach_key, in_len_key );

        //----------------------------------------
        // search if entry already exists:
        //----------------------------------------
        bo_ret = m_htree1_avl_search( NULL,
                                      ads_avl_cntl,
                                      &ds_avl_work,
                                      &ads_resource->dsc_sort );
        if ( bo_ret == FALSE || ds_avl_work.adsc_found != NULL ) {
            return false;
        }

        //----------------------------------------
        // insert entry:
        //----------------------------------------
        bo_ret = m_htree1_avl_insert( NULL,
                                      ads_avl_cntl,
                                      &ds_avl_work,
                                      &ads_resource->dsc_sort );
        if ( bo_ret == FALSE ){ return false; }
    }
	else if ( ads_res->ads_child->ien_type == ied_tag )
	{
        bo_ret = m_insert_res(	adsl_wsp_helper, adsp_workarea,
								ads_avl_cntl,
								ads_res->ads_child, ach_key, in_len_key );
       
		if ( bo_ret == FALSE ){ return false; }
	}
    
    if ( ads_res->ads_next != NULL )
	{
        return m_insert_res( adsl_wsp_helper, adsp_workarea,
							 ads_avl_cntl,
                             ads_res->ads_next, ach_prefix, in_len_prefix );
    }
    return true;
} // end of ds_resource::m_init_res


/**
 * function ds_resource::m_insert_lang
 * insert language inside avl tree
 *
 * @param[in]   ds_wsp_helper*  adsl_wsp_helper         wsp helper class
 * @param[in]   const char*     ach_file                filename
 * @param[in]   int             in_len_file             length of filename
 * @return      bool                                    true = success
*/
bool ds_resource::m_read_file( ds_wsp_helper* adsl_wsp_helper, const char* ach_file, int in_len_file, struct dsd_hl_aux_diskfile_1* adsp_file, ds_xml* adsp_xml )
{
    // initialize some variables:
    bool                            bo_ret;             // return value
    ds_xml                          dsc_xml;            // xml parser class
    char*                           ach_xml;            // read in xml data
    int                             in_len;             // length of xml data
    const char*                           ach_name;           // name of xml tag
    int                             in_len_name;        // length of xml tag name
    dsd_xml_tag*                    ads_xml;            // xml chain

    //----------------------------------------
    // try to open file:
    //----------------------------------------
    if ( ach_file == NULL || in_len_file < 1 ) {
        return false;
    }    
    memset(adsp_file, 0, sizeof(struct dsd_hl_aux_diskfile_1));
#ifndef WSP_V24
    adsp_file->ac_name      = (void*)ach_file;
    adsp_file->inc_len_name = in_len_file;
    adsp_file->iec_chs_name = ied_chs_utf_8;
#endif
#ifdef WSP_V24
    adsp_file->dsc_ucs_file_name.ac_str      = (void*)ach_file;
    adsp_file->dsc_ucs_file_name.imc_len_str = in_len_file;
    adsp_file->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
#endif

    bo_ret = adsl_wsp_helper->m_cb_file_access( adsp_file );
    if ( bo_ret == false ) {
        return false;
    }

    ach_xml = adsp_file->adsc_int_df1->achc_filecont_start;
    in_len  = (int)(adsp_file->adsc_int_df1->achc_filecont_end - adsp_file->adsc_int_df1->achc_filecont_start);
    if ( ach_xml == NULL || in_len < 1 ) {
        adsl_wsp_helper->m_cb_file_release( adsp_file );
        return false;
    }

    //----------------------------------------
    // read xml data:
    //----------------------------------------
    //dsc_xml.m_init( adsl_wsp_helper );
    ads_xml = adsp_xml->m_from_xml( ach_xml, in_len );
    if ( ads_xml == NULL ) {
        adsl_wsp_helper->m_cb_file_release( adsp_file );
        return false;
    }
    
    //----------------------------------------
    // check for language tag:
    //----------------------------------------
    adsp_xml->m_get_node_name( ads_xml, &ach_name, &in_len_name );
    if (    ach_name == NULL
         || in_len_name != (int)strlen(DEF_FIRST_TAG)
         || memcmp( ach_name, DEF_FIRST_TAG, in_len_name ) != 0 ) {
        adsl_wsp_helper->m_cb_file_release( adsp_file );
        return false;
    }

    return true;
} // end of ds_resource::m_read_file


/**
 * static function ds_resource::m_avl_lang_compare
 *
 * @param[in]   void*                               currently unused userfield
 * @param[in]   dsd_htree1_avl_entry* ads_entry1    avl entry
 * @param[in]   dsd_htree1_avl_entry* ads_entry2    avl entry
 * @return      int                                 compare result
*/
int ds_resource::m_avl_lang_compare( void*,
                                struct dsd_htree1_avl_entry* ads_entry1,
                                struct dsd_htree1_avl_entry* ads_entry2 )
{
    // initialize some variables:
    dsd_language_sort* ads_sort1;
    dsd_language_sort* ads_sort2;

    ads_sort1 = (dsd_language_sort*)((char *) ads_entry1 - offsetof( dsd_language_sort, dsc_sort ));
    ads_sort2 = (dsd_language_sort*)((char *) ads_entry2 - offsetof( dsd_language_sort, dsc_sort ));

    return ads_sort1->in_language - ads_sort2->in_language;
} // end of ds_resource::m_avl_lang_compare


/**
 * static function ds_resource::m_avl_compare
 *
 * @param[in]   void*                               currently unused userfield
 * @param[in]   dsd_htree1_avl_entry* ads_entry1    avl entry
 * @param[in]   dsd_htree1_avl_entry* ads_entry2    avl entry
 * @return      int                                 compare result
*/
int ds_resource::m_avl_compare( void*,
                                struct dsd_htree1_avl_entry* ads_entry1,
                                struct dsd_htree1_avl_entry* ads_entry2 )
{
    // initialize some variables:
    dsd_resource_sort* ads_sort1;
    dsd_resource_sort* ads_sort2;
    int                in_ret;

    ads_sort1 = (dsd_resource_sort*)((char *) ads_entry1 - offsetof( dsd_resource_sort, dsc_sort ));
    ads_sort2 = (dsd_resource_sort*)((char *) ads_entry2 - offsetof( dsd_resource_sort, dsc_sort ));

    if ( ads_sort1->uin_hash > ads_sort2->uin_hash ) {
        in_ret = 1;
    } else if ( ads_sort1->uin_hash < ads_sort2->uin_hash ) {
        in_ret = -1;
    } else {
        if ( ads_sort1->in_len_key > ads_sort2->in_len_key ) {
            in_ret = 1;
        } else if ( ads_sort1->in_len_key < ads_sort2->in_len_key ) {
            in_ret = -1;
        } else {
            in_ret = memcmp( ads_sort1->ach_key, ads_sort2->ach_key, ads_sort1->in_len_key );
        }
    }
    return in_ret;
} // end of ds_resource::m_avl_compare

    
/**
 * function ds_resource::m_get_hash
 *
 * @param[in]   const char*     ach_in
 * @param[in]   int             in_len_in
 * @return      unsigned int
*/
unsigned int ds_resource::m_get_hash( const char* ach_in, int in_len_in ) const
{
   int uin_hash = 5381;

   for(int in_1 = 0; in_1 < in_len_in; in_1++)
   {
      uin_hash = ((uin_hash << 5) + uin_hash) + ach_in[in_1];
   }
   return uin_hash;
} // end of ds_resource::m_get_hash
