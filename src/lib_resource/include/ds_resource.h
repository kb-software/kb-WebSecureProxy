#ifndef DS_RESOURCE_H
#define DS_RESOURCE_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_resource                                                           |*/
/*|                                                                         |*/
/*| DESCRIPTION:                                                            |*/
/*| ============                                                            |*/
/*|   handle resources (language depentend stuff) for server-datahooks      |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   June 2009                                                             |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
struct dsd_xml_tag;             // forward definition
class  ds_wsp_helper;           // forward definition
struct dsd_htree1_avl_entry;    // forward definition
struct dsd_htree1_avl_cntl;     // forward definition
class  ds_xml;
class ds_resource
{
public:
    // constructor/destructor:
    ds_resource();
    ~ds_resource();

    // new operator:
    void* operator new(size_t, void* av_location) {
        return av_location;
    }
    // avoid warning:
    void operator delete( void*, void* ) {};

    // setup function:
    bool m_setup( ds_wsp_helper* adsl_wsp_helper, const char* ach_file, int in_len_file, struct dsd_aux_get_workarea* adsp_workarea );

    // get resource functions:
    bool m_get( int in_lang,
                const char* ach_key, int in_len_key,
                const char** aach_res, int* ain_len ) const;
    bool m_get( int in_lang, const char* ach_key,
                const char** aach_res, int* ain_len ) const;

    // count supported languages:
    int m_count_lang() const;

    // get type of language:
    int  m_parse_lang( const char* ach_lang, int in_len ) const;
    bool m_get_lang  ( int in_lang, const char** aach_lang, int* ain_len ) const;
    
private:
    // variables:
    struct dsd_htree1_avl_cntl  ds_avl_control;     // avl control structure
    char*                       ach_cache;          // cached xml structure
    int                         in_len_cache;       // length of cache
    int                         in_no_lang;         // number off supported languages

    // search functions:
    void* m_search_lang( int in_key ) const;
    void* m_search_res ( dsd_htree1_avl_cntl* ads_avl_cntl,
                         const char* ach_key, int in_len_key ) const;

    // setup functions:
    bool m_init_avl();
    bool m_insert_lang( ds_wsp_helper* adsl_wsp_helper, dsd_xml_tag* ads_lang, struct dsd_aux_get_workarea* adsp_workarea );
    bool m_insert_res ( ds_wsp_helper* adsl_wsp_helper,
						struct dsd_aux_get_workarea* adsp_workarea, 
                        dsd_htree1_avl_cntl* ads_avl_cntl, dsd_xml_tag* ads_res,
                        const char* ach_prefix = NULL, int in_len_prefix = 0 );
    bool m_read_file( ds_wsp_helper* adsl_wsp_helper, const char* ach_file, int in_len_file, struct dsd_hl_aux_diskfile_1* adsp_file, ds_xml* adsp_xml );

    // static compare functions:
    static int m_avl_lang_compare( void*,
                                  struct dsd_htree1_avl_entry* ads_entry1,
                                  struct dsd_htree1_avl_entry* ads_entry2 );
    static int m_avl_compare( void*,
                              struct dsd_htree1_avl_entry* ads_entry1,
                              struct dsd_htree1_avl_entry* ads_entry2 );

    // hash function:
    unsigned int m_get_hash( const char* ach_in, int in_len_in ) const;

};
#endif //DS_RESOURCE_H
