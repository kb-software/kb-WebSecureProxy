"use strict";
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|    settings.js                                                      |*/
/*|       a javascript library for user settings page, which supports   |*/
/*|       moving, adding, deleting and validation of the content        |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|    Michael Jakobs, Apr. 2010                                        |*/
/*|                                                                     |*/
/*| Version:                                                            |*/
/*| ========                                                            |*/
/*|    1.0                                                              |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|    Beljajew Georg, May. 2016                                        |*/
/*|                                                                     |*/
/*| Version:                                                            |*/
/*| ========                                                            |*/
/*|    2.0 complet overhaul to remove redundances                       |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ==========                                                          |*/
/*|    HOB GmbH Germany                                                 |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/



var boc_first_run = true;
var boc_singleCheck = true;

var dsg_current_div;

/**
* public function m_clean_hidden
* for fixing isue with second entry because 
* password manager has filled hidden text fields.
*/
function m_clean_hidden()
{
    var stuffToClean = document.querySelectorAll( ".clean" );
    
    for( var i = 0; i < stuffToClean.length; i++ )
    {
        stuffToClean[i].value = "";
    }
    
}

/**
 * public function m_show_first
 * show first tab of our settings and hide all the others
 *
 * @return      nothing
*/
function m_show_first()
{
    //modification for input
    var dsl_input = document.querySelectorAll( 'input:not([type="submit"]), select' );
    for( var i = 0; i < dsl_input.length; i++)
    {
        dsl_input[i].addEventListener('change', function(){
            bog_modified = true;
        });
    }
    
    var strl_id, dsl_link;
    if(location.hash && location.hash.length > 1) {
        switch(location.hash) {
            case '#wsg':
                strl_id = "wsg-bookmark-settings";
                dsl_link = document.getElementById('open-wsg');
            break;
            case '#bookmarks':
                strl_id = "rdvpn-bookmark-settings";
                dsl_link = document.getElementById('open-rdvpn');
            break;
            case '#applications':
                strl_id = "portlet-settings";
                dsl_link = document.getElementById('open-portlet');
            break;
            case '#dod':
                strl_id = "desktop-on-demand-settings";
                dsl_link = document.getElementById('open-dod');
            break;
            case '#other':
                strl_id = "other-settings";
                dsl_link = document.getElementById('open-other');
            break;
        }
    }
    if(!strl_id) {
        dsl_link = document.querySelector("#menu a[onclick]");
        var strl_value = dsl_link.getAttribute( "onclick" );
        if ( !strl_value ) {
            return;
        }

        strl_value = strl_value.replace( /(m_show\(')/i, "" );
        strl_id = strl_value.replace( /(', this)(\);(return false;)?)/i, "" );
    }
    m_show(strl_id, dsl_link);
} // end of m_show_first

/**
 * public function m_show
 * show one tab of our settings and hide all the others
 *
 * @param[in]   string      str_id          id from tab to show
 * @param[in]   object      ds_object       object to be highlighted
 * @return      nothing
*/
function m_show( str_id, ds_object )
{
    var dsl_member;
    var strl_value;
    var dsl_links;
    var inl_pos;

    // do validation:
    if( !boc_first_run )
        if ( !m_validate() ) {
            return;
        }
    
    boc_first_run = false;
    
    var dsl_containers = document.querySelectorAll( '#settings > div:not(.closed)' );
    
    for(inl_pos=0; inl_pos<dsl_containers.length; inl_pos++) {
        dsl_containers[inl_pos].className += " closed";
    }
    
    dsg_current_div = document.getElementById(str_id);
    if(dsg_current_div) {
        dsg_current_div.className = dsg_current_div.className.replace(/closed/, ' ');
    }

    // select menu entry:
    dsl_links = document.querySelectorAll("#menu a.selected" );

    for ( inl_pos = 0; inl_pos < dsl_links.length; inl_pos++ ) {
        m_deselect( dsl_links[inl_pos] );
    }
    
    m_select( ds_object );
} // end of m_show

/**
 * function m_select
 * select (means highlight) given menu entry
 *
 * @param[in]   object      dsp_menu
 * @return      nothing
*/
function m_select( dsp_menu )
{
    m_add_class(dsp_menu, "selected");
} // end of m_select

/**
 * function m_deselect
 * deselect given menu entry
 *
 * @param[in]   object      dsp_menu
 * @return      nothing
*/
function m_deselect( dsp_menu )
{
    m_remove_class(dsp_menu, "selected");
} // end of m_deselect

function m_get_parent_by_tag(dsp_button, str_tag) {
    if(!str_tag)
        str_tag = 'tr'
    var ds_el = dsp_button;
    while ((ds_el = ds_el.parentElement) && ds_el.tagName.toLowerCase() != str_tag);
    return ds_el;
}

function m_highlight(dsp_element) {
    m_add_class(dsp_element, 'moved');
    setTimeout(function(){
        m_remove_class(dsp_element, 'moved');
    }, 500);
}

/**function m_add()
* add a new entry into current settings div
*
*@return    nothing
*/
function m_add()
{
    var dsl_dummy = dsg_current_div.querySelector( ".dummy > *" ).cloneNode( true );
    var str_selector = ".containerTable";
    if(dsl_dummy.tagName.toLowerCase() == 'tr') {
        str_selector+=' tbody';
    }
    
    var dsl_container = dsg_current_div.querySelector( str_selector );
    
    /*
    //create a manual copy of script elements as cloning it does not reexecute the code
    var adsl_scripts = dsl_dummy.getElementsByTagName("script");
    for (var inl1=0; inl1<adsl_scripts.length; inl1++) {
        var dsl_sc = document.createElement("script");
        dsl_sc.innerText = adsl_scripts[inl1].innerText;
        adsl_scripts[inl1].parentElement.insertBefore(dsl_sc, adsl_scripts[inl1]);
        adsl_scripts[inl1].parentElement.removeChild(adsl_scripts[inl1]);
    }*/
    
    dsl_container.appendChild( dsl_dummy );
    m_highlight(dsl_dummy);
    m_update_bm_events();
    bog_modified = true;
}//function m_add()

/**function m_up( inp_row )
* moves an entry one position higher
*/
function m_up( dsp_button )
{
    var str_tag = 'tr';
    var dsl_table = m_get_parent_by_tag(dsp_button, 'table');
    if(m_has_class(dsl_table, 'reorder-groups')) {
        str_tag = 'tbody';
    }
    
    var dsl_row = m_get_parent_by_tag(dsp_button, str_tag);
    
    dsl_row.parentElement.insertBefore(dsl_row, dsl_row.previousElementSibling);
    m_highlight(dsl_row);
    bog_modified = true;
}//function m_up( inp_row )

/**function m_down( inp_row )
* moves an entry one position lower
*/
function m_down( dsp_button )
{
    var str_tag = 'tr';
    var dsl_table = m_get_parent_by_tag(dsp_button, 'table');
    if(m_has_class(dsl_table, 'reorder-groups')) {
        str_tag = 'tbody';
    }
    
    var dsl_row = m_get_parent_by_tag(dsp_button, str_tag);
    
    dsl_row.parentElement.insertBefore(dsl_row.nextElementSibling, dsl_row);
    m_highlight(dsl_row);
    bog_modified = true;
}//function m_down( inp_row )

/**function m_remove( inp_row )
* removes one entry
*/
function m_remove( dsp_button )
{
    var str_tag = 'tr';
    var dsl_table = m_get_parent_by_tag(dsp_button, 'table');
    if(m_has_class(dsl_table, 'reorder-groups')) {
        str_tag = 'tbody';
    }
    var dsl_row = m_get_parent_by_tag(dsp_button, str_tag);
    
    dsl_row.parentElement.removeChild(dsl_row);
    bog_modified = true;
}//function m_remove( inp_row )

/** function m_change( inp_num )
 * switch old entry into "pin change" mode
 */
function m_change( inp_num )
{
    if( inp_num < 0 )
        return;
    
    var dsl_container = dsg_current_div.querySelectorAll(".containerTable tbody")[0];
    
    if( !dsl_container )
        return;
    
    if( !dsl_container.rows )
        return;
    
    if( inp_num >= dsl_container.rows.length )
        return;
    
    var ds_row = dsl_container.rows[ inp_num ];
    
    var dsr_hidden = ds_row.querySelectorAll( ".hiddenPin" );
    
    for( var i = 0; i < dsr_hidden.length; i++)
    {
        dsr_hidden[ i ].querySelectorAll( ".text" )[0].value = "";
        
        dsr_hidden[ i ].className = "";
    }
    
    ds_row.querySelectorAll( ".change" )[0].style.visibility = "hidden";
    
}// m_change( inp_num )

/**
 * function m_validate
 * validates all input fields in current active div.
 *
 * @return true if current div is ok
 */
function m_validate( dsp_check )
{
    var dsl_container = dsp_check
    if( !dsp_check ) {
        // if dsp_check is not specified then we need to check current.
        dsl_container = dsg_current_div.querySelectorAll( ".checkTable" )[0];
    }
    
    if( !dsl_container ) {
        // if there is no "checkTable" then there is nothing that can be wrong.
        return true;
    }
    var dsl_dummy = dsl_container.parentElement.querySelector( ".dummy" );
    if( !dsl_dummy ) {
        dsl_dummy = document.createElement('div');
        //just use an empty as replacement, should not happen anyways
    }
    
    var str_dataset_containers = 'tbody tr'; //do not select head row
    if(m_has_class(dsl_container, 'reorder-groups')) {
        //table consists of multiple tbody's; each tbody instead of each tr forms a dataset (DoD-Config)
        str_dataset_containers = 'tbody';
    }        
    
    var dslr_datasets = dsl_container.querySelectorAll(str_dataset_containers);
    
    if( !dslr_datasets || dslr_datasets.length == 0 ) {
        return true; // nothing to check
    }
    
    var bol_valide = true;
    boc_singleCheck = false;

    for(var i = 0; i < dslr_datasets.length; i++ )
    {
        var bol_all_default = true;
        var bol_row_valid = true;
        var dsl_row = dslr_datasets[i];
        var dslr_row_inputs = dsl_row.querySelectorAll( ".text" )
        
        for(var j = 0; j < dslr_row_inputs.length; j++) {
            if( !m_check( dslr_row_inputs[j] ) ) {
                bol_row_valid = false;
            }
            var dsl_def_element = dsl_dummy.querySelector('[name="'+dslr_row_inputs[j].name+'"]');
            var defVal = dsl_def_element ? dsl_def_element.value : "";
            if(dslr_row_inputs[j].value && dslr_row_inputs[j].value != defVal) {
                bol_all_default = false;
            }
        }
        
        if(!bol_row_valid) {
            if(bol_all_default) {
                dsl_row.parentElement.removeChild(dsl_row);
                //delete empty rows
            } else {
                bol_valide = false;
            }
        }
        
    }

    boc_singleCheck = true;

    return bol_valide;
}

function m_swap_portlets(dsp_this, dsp_other) {
    var strl_title = dsp_other.title;
    var strl_class = dsp_other.className;
    dsp_other.title = dsp_this.title;
    dsp_other.className = dsp_this.className;
    dsp_this.title = strl_title;
    dsp_this.className = strl_class;
}

function m_set_default_portlet(dsp_clicked, strp_portlet) {
    var dsp_other;
    if(!m_has_class(dsp_clicked, 'portlet-name')) {
        //icon clicked
        dsp_clicked = dsp_clicked.parentElement.querySelector('.portlet-name');
    }
    if(m_has_class(dsp_clicked, 'default')) {
        //already selected: swap with invisible nodefault span
        dsp_other = document.getElementById('portlet_select_nodefault');
        strp_portlet = "";
    } else {
        dsp_other = document.querySelector("#portlets table span.default");
        //ensure portlet is visible
        var dsp_open = m_get_parent_by_tag(dsp_clicked, 'tr').querySelector('input[id^="open"]');
        dsp_open.checked = true;
    }
    //swap classes and title (description on hover)
    m_swap_portlets(dsp_clicked, dsp_other);
    //update default portlet
    document.getElementById('select_default_portlet').value = strp_portlet
    
    bog_modified = true;
}

function m_default_portlet_changed(dsp_select) {
    var strl_portlet = dsp_select.value;
    if(!strl_portlet) {
        strl_portlet="nodefault";
    }
    var dsp_current = document.getElementById('portlet_select_'+strl_portlet);
    var dsp_other = document.querySelector("#portlets table span.default");
    
    //swap classes and title (description on hover)
    m_swap_portlets(dsp_current, dsp_other);

    if(strl_portlet != "nodefault"){
        //ensure portlet is visible
        var dsp_open = m_get_parent_by_tag(dsp_current, 'tr').querySelector('input[id^="open"]');
        dsp_open.checked = true;
        
    }
}

/** m_check_and_submit
 * check all entries, then submit if all of them are ok
 */
function m_check_and_submit( dsp_form )
{
    var dslr_containers = document.querySelectorAll( ".checkTable" );

    if( !dslr_containers ) return;
    if( !dslr_containers.length ) return;

    var bol_valide = true;

    for( var i = 0; i < dslr_containers.length; i++ )
    {
        if( !m_validate( dslr_containers[i] ) )
            bol_valide = false;
    }

    if( bol_valide )
        dsp_form.submit();

}

/** function m_check( ds_input )
 * check an input field and mark it, if its content is not valide
 */
function m_check( ds_input )
{
    var strl_name;
    var strl_id;
    var strl_value;
    var bol_valid;

    strl_name = ds_input.getAttribute( "name" );
    
    if ( !strl_name ) {
        if( ds_input.className.indexOf( "pin" ) > -1 ) // we don't need to send two pins so one of them has no name.
            return m_is_pin( ds_input );
        return;
    }

    strl_value = ds_input.value;

    if ( !strl_value ) {
        bol_valid = false;
    }


    // name validation:
    else if ( strl_name.indexOf("name") > -1 ) {
        if(strl_value.trim() != strl_value) {
            strl_value = ds_input.value = strl_value.trim();
        }
        bol_valid = m_is_name( strl_value );
    }

    // hlc ws name
    else if( strl_name.indexOf("hlc-wstat") > -1 )
        bol_valid = m_is_hlc_name( strl_value );

    // url validation:
    else if ( strl_name.indexOf("url") > -1 ) {
        // Mr. Galea advised: no check for wfa:
        strl_id = ds_input.getAttribute("id");
        var strl_type = ds_input.getAttribute("data-type");
        if (    strl_id
             && strl_id.indexOf("wfa") > -1 ) {
            bol_valid = typeof(strl_value) == "string";
        } else if(strl_type == "rdvpn") {
            // skip autocompletion for rdvpn (user portal) bookmarks -> can be relative paths
            bol_valid = m_is_url( strl_value, true);
        } else {
            // autocomplete "www.hob.de" to "http://www.hob.de"
            if ( strl_value.indexOf("://") < 0 ) {
                ds_input.value = "http://" + strl_value;
                strl_value = ds_input.value;
            }
            bol_valid = m_is_url( strl_value );
        }
    }

    // INETA validation:
    else if ( strl_name.indexOf("ineta") > -1 ) {
        strl_value = strl_value.replace (/^\s+/, '').replace (/\s+$/, '');
        ds_input.value = strl_value;
        bol_valid = m_is_ineta( strl_value );
    }

    // port validation:
    else if ( strl_name.indexOf("port") > -1 ) {
        bol_valid = m_is_port( strl_value );
    }

    // mac address validation:
    else if ( strl_name.indexOf("mac") > -1 ) {
        strl_value = strl_value.replace (/^\s+/, '').replace (/\s+$/, '');
        ds_input.value = strl_value;
        bol_valid = m_is_mac( strl_value );
    }

    // timeout validation:
    else if ( strl_name.indexOf("timeout") > -1 ) {
        bol_valid = m_is_timeout( strl_value );
    }
    
    else if ( strl_name.indexOf("pin") > -1 ) {
        return m_is_pin( ds_input );
    }
    

    if ( bol_valid ) {
        m_unmark   ( ds_input );
    } else {
        m_mark     ( ds_input );
        if( boc_singleCheck )
            alert( strg_error_msg );
    }

    return bol_valid;
}//m_check( ds_input )

/**
 * function m_mark
 * mark a given input field
 *
 * @param[in]   object  ds_input    input field
 * @return      nothing
 */
function m_mark( ds_input )
{
    var strl_class = ds_input.getAttribute( "class" );
    if ( strl_class ) {
        if ( strl_class.indexOf( "marked" ) < 0 ) {
            ds_input.setAttribute( "class", strl_class + " marked" );
        }
    } else {
        ds_input.setAttribute( "class", "marked" );
    }
    ds_input.focus();
} // end of m_mark

/**
 * function m_unmark
 * unmark a given input field
 *
 * @param[in]   object  ds_input    input field
 * @return      nothing
 */
function m_unmark( ds_input )
{
    var strl_class = ds_input.getAttribute( "class" );
    if ( strl_class ) {
        ds_input.setAttribute( "class", strl_class.replace( / marked/, "" ) );
    }
} // end of m_unmark

/**
 * private function m_is_timeout
 * check if given string is a timeout
 *
 * @param[in]   string  str_timeout timeout
 * @return      true if number and in range
 */
function m_is_timeout( str_timeout )
{
    var inl_tout;

    if (    (str_timeout - 0) != str_timeout 
         || str_timeout.length < 1 ) {
        return false;
    }

    inl_tout = parseInt( str_timeout, 10 );
    if ( inl_tout > 0 && inl_tout < 24 * 3600 ) {
        return true;
    }
    return false;
} // end of m_is_timeout

/**
 * private function m_is_mac
 * check if given string is a mac address
 *
 * @param[in]   string  str_mac     mac address
 * @return      true if mac address.
 */
function m_is_mac( str_mac )
{
    var dsl_regex=/^([0-9a-f]{2}([:-]|$)){6}$|([0-9a-f]{4}([.]|$)){3}$/i;
    return dsl_regex.test( str_mac ) || str_mac == "0";
} // end of m_is_mac

/**
 * private function m_is_name
 * check if given string is a name
 *
 * @param[in]   string  str_name    name
 * @return      true if this name contains only letters, numbers -_.
 */
function m_is_name( str_name )
{
    //old: /[\wäöü]+([\w \.-äöü]*)?/i;
    //Allow the whole printable ASCII range and umlauts 
    var dsl_regex=/^[\x21-\x7Eäöü]([\x21-\x7Eäöü ]*[\x21-\x7Eäöü])?$/i;
    return dsl_regex.test( str_name );
} // end of m_is_name

/**
 * private function m_is_url
 * check if given string is an url
 *
 * @param[in]   string  str_url     url
 * @return      nothing
 */
function m_is_url( str_url, bop_relative )
{
    var dsl_regex = /^(https?):\/\/(([a-z0-9$_\.\+!\*\'\(\),;\?&=-]|%[0-9a-f]{2})+(:([a-z0-9$_\.\+!\*\'\(\),;\?&=-]|%[0-9a-f]{2})+)?@)?((([a-z0-9][a-z0-9-]*[a-z0-9]\.)*[a-z]{1}[a-z0-9-]*[a-z0-9]|((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2}))(:\d+)?)(((\/+([a-z0-9$_\.\+!\*\'\(\),;:@&=-]|%[0-9a-f]{2})*)*(\?([a-z0-9$_\.\+!\*\'\(\),;:@&=-]|%[0-9a-f]{2})*)?)?)?(#([a-z0-9$_\.\+!\*\'\(\),;:@&=-]|%[0-9a-f]{2})*)?$/i;
    //Note relative regex matches host relative (ie absolute) urls: /public/login.hsl but not login.hsl 
    var dsl_relative = /^(((\/+([a-z0-9$_\.\+!\*\'\(\),;:@&=-]|%[0-9a-f]{2})*)*(\?([a-z0-9$_\.\+!\*\'\(\),;:@&=-]|%[0-9a-f]{2})*)?)?)?(#([a-z0-9$_\.\+!\*\'\(\),;:@&=-]|%[0-9a-f]{2})*)?$/i;
    return dsl_regex.test( str_url ) || (bop_relative && dsl_relative.test(str_url));
} // end of m_is_url

/**
 * private function m_is_ineta
 * check if given string is an ineta/hostname
 *
 * @param[in]   string  str_ineta   ineta
 * @return      nothing
 */
function m_is_ineta( str_ineta )
{
    var dsl_regex = /^(([a-z0-9$_\.\+!\*\'\(\),;\?&=-]|%[0-9a-f]{2})+(:([a-z0-9$_\.\+!\*\'\(\),;\?&=-]|%[0-9a-f]{2})+)?@)?(([a-z0-9][a-z0-9-]*[a-z0-9]\.)*[a-z]{1}[a-z0-9-]*[a-z0-9]|((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2}))$/i;
    //regex must match full input
    return dsl_regex.test( str_ineta );
} // end of m_is_ineta

/**
 * private function m_is_port
 * check if given string is a port
 *
 * @param[in]   string  str_port    port
 * @return      true if str_port is valide port.
 */
function m_is_port( str_port )
{
    var inl_port;

    if (    (str_port - 0) != str_port 
         || str_port.length < 1 ) {
        return false;
    }

    inl_port = parseInt( str_port, 10 );
    if (    inl_port >= 0
         && inl_port <= 65535 ) {
        return true;
    }
    return false;
} // end of m_is_port

/** function m_is_pin( ds_pin1 )
 * @param ds_pin1 not string but node
 *
 * @return true if both pins are in range and equal or if it is to early to determenate this.
 */
function m_is_pin( ds_pin1 )
{
    var str_pin1 = ds_pin1.value;

    if( ds_pin1.className.indexOf( "old" ) > -1 && str_pin1 == "#" )
        return true;

    var str_class = ( ds_pin1.className.indexOf( "pinRepeat" ) > -1 ) ? ".pin" : ".pinRepeat";

    var ds_pin2;
    for( var ds_parent = ds_pin1.parentNode;
         !( ds_pin2 = ds_parent.querySelectorAll( str_class )[0] );
         ds_parent = ds_parent.parentNode
        )
    ;

    var str_pin2 = ds_pin2.value;
    
    if( ds_pin2.className.indexOf( "old" ) > -1 && str_pin2 == "#" )
        return true;

    if( boc_singleCheck ) // we stil editing
        if( ( !str_pin1 && str_pin2 ) || ( str_pin1 && !str_pin2 ) ) // we need both to decide
        {
            m_unmark( ds_pin1 );
            m_unmark( ds_pin2 );
            return true;
        }

    if( str_pin1.length < 3 || str_pin1.length > 20 )
        return false;
    
    if( !m_is_name( str_pin1 ) )
    {
        m_mark( ds_pin1 );
        if( boc_singleCheck )
            alert( strg_error_msg );
        return false;
    }
    
    if( !m_is_name( str_pin2 ) )
    {
        m_mark( ds_pin2 );
        if( boc_singleCheck )
            alert( strg_error_msg );
        return false;
    }

    if( str_pin1 != str_pin2 )
    {
        var ds_second_pin = ( str_class.indexOf( "Repeat" ) > -1 ) ? ds_pin2 : ds_pin1;
        m_mark( ds_second_pin );
        if( boc_singleCheck )
            alert( strg_error_msg );
        return false;
    }
    
    m_unmark( ds_pin1 );
    m_unmark( ds_pin2 );

    return true;
}// end of m_is_pin

/** function m_is_hlc_name
 * checks if this name is ok and if there was no equal names
 */
function m_is_hlc_name( strp_name )
{
    var inl_count = 0;
    var dsl_hlc = document.getElementById( "hoblink-cert-settings" );
    var dsr_names = dsl_hlc.querySelectorAll( ".hlcWsName" );
    
    for( var inl_i = 0; inl_i < dsr_names.length; inl_i++ ) {
        if( dsr_names[ inl_i ].value == strp_name ) inl_count++;
    }
    
    return ( inl_count == 1 && m_is_name( strp_name ) );
}





function m_update_bm_select(event) {
    var sel = event.target.value
    var root = event.target.parentElement.parentElement;
    
    var cont = root.querySelectorAll(".bm-portlet-config div.selected");
    var current = root.querySelector(".bm-config-"+sel);
    
    for(var inl1=0;inl1<cont.length; inl1++) {
        m_remove_class(cont[inl1], "selected");
    }
    
    m_add_class(current, "selected");
    var input = current.querySelector(".href");
    var value = "";
    if(input.tagName.toLowerCase() == "select") {
        if(input.selectedIndex != -1)
            value = input.options[input.selectedIndex].value
    } else {
        value = input.value;
    }
    
    var output = root.querySelector('input[name="bmark-url"]');
    output.value = value;
    m_unmark(output); //remove error flag
}

function m_update_bm_events() {
    var uninitialised = document.querySelectorAll("tbody .bm-config:not(.has-events)");
    for(var inl1=0;inl1<uninitialised.length; inl1++) {
        m_bind_bm_events(uninitialised[inl1]);
    }
}

function m_bm_changed(event) {
    var cur = event.target.value;
    var root = m_get_parent_by_tag(event.target, "td");
    var output = root.querySelector('input[name="bmark-url"]');
    output.value = cur;
    output.onchange();  //revalidate field
}

function m_bind_bm_events(dsp_div) {
    var selects = dsp_div.querySelectorAll(".href");
    for(var inl1=0; inl1<selects.length; inl1++) {
        selects[inl1].onchange = m_bm_changed;
    }
    m_add_class(dsp_div, "has-events");
    var options = dsp_div.querySelectorAll(".bm-portlet-config option");
    for(var inl1=0; inl1<options.length; inl1++) {
        dsg_bm.m_prepare_link(options[inl1]);
    }
    
    
    var input = dsp_div.querySelector('input[name="bmark-url"]');
    var dsl_url = input.value;
    var portlet = dsg_bm.m_get_portlet(dsl_url);
    
    //if this is an existing bookmark select the corresponding portlet (and config)
    if(portlet) {
        var dsl_select = dsp_div.querySelector('select.bm-portlet-switch');
        dsl_select.value = portlet;
        if(dsl_select.selectedIndex == -1) {
            //portlet does not exist
            dsl_select.value = "unknown";
            m_add_class(dsp_div.querySelector(".bm-config-unknown"), "selected");
        } else {
            m_add_class(dsp_div.querySelector(".bm-config-"+portlet), "selected");
            
            var input = dsp_div.querySelector('.bm-config-'+portlet+' .href');
            if(!input) {
                
            } else if(input.tagName.toLowerCase() == "input" && input.type != "hidden") {
                input.value = dsl_url;
            } else if(input.tagName.toLowerCase() == "select") {
                input.value = dsl_url;
            }
        }
    }
}

