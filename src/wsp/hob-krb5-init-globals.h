
struct dsd_global_and_static NAME_OF_MAIN_LOC_GLOB = {
    (( void * )0 )
    ,
    (( void * )0 )
    ,
    0
    ,
    -1
    ,
    ads_conf->aa_temp_memory_area
    ,

    4096
    /*,
    ""*/
    ,

    (( void * )0 )
    ,
    {0,0,0,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    0,
    0,

    1,
    1,
    1,
    1,
    1,
    ( void* )0,
    0,
    ads_conf->aa_memory_area ,ads_conf->a_tracer ,
    ads_conf->in_trace_lvl, ads_conf->a_ip_address_context,
    0,
    ( void* )0

};
struct dsd_global_and_static NAME_OF_MAIN_LOC_GLOB = m_init_dsd_global_and_static(
                                                            ads_conf->aa_temp_memory_area, 
                                                            ads_conf->aa_memory_area, 
                                                            ads_conf->a_tracer, 
                                                            ads_conf->in_trace_lvl, 
                                                            ads_conf->a_ip_address_context);
struct dsd_global_and_static * NAME_OF_MAIN_LOC_GLOB_P =&NAME_OF_MAIN_LOC_GLOB;
//NAME_OF_MAIN_LOC_GLOB_P->error_string = (char*)m_aux_stor(NAME_OF_MAIN_LOC_GLOB_P->aa_temp_memory_area,
//                                            256);