/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|    admin.js                                                         |*/
/*|       a javascript library for administration page                  |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|    Michael Jakobs, May 2010                                         |*/
/*|                                                                     |*/
/*| Version:                                                            |*/
/*| ========                                                            |*/
/*|    1.0                                                              |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ==========                                                          |*/
/*|    HOB GmbH Germany                                                 |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| globals:                                                            |*/
/*+---------------------------------------------------------------------+*/
var dsg_date    = new dsd_date();
var dsg_query   = new dsd_query();
var dsg_context = new dsd_context_menu();
var dsg_form    = new dsd_form();
var dsg_table   = new dsd_table();

/*+---------------------------------------------------------------------+*/
/*| context menu object:                                                |*/
/*|   create a context menu with given element (by its id)              |*/
/*+---------------------------------------------------------------------+*/
function dsd_context_menu() {
    this.boc_hide    = true;
    this.dsc_menu    = null;
    this.inc_mouse_y = 0;
    this.inc_mouse_y = 0;


    /**
     * public function m_show
     * show context menu
     *
     * @param[in]   event   ds_event        click event
     * @param[in]   string  str_id          id of element to show
    */
    this.m_show = function( ds_event, str_id )
    {
        // get event:
        if ( !ds_event ) {
            ds_event = window.event;
        }

        // check for input field targets:
        if ( this.m_check_target( ds_event ) == false ) {
            return true;
        }

        // get actual mouse position:
        this.m_get_mouse( ds_event );
        
        // load menu content:
        this.m_load_menu( str_id );
        if ( this.dsc_menu ) {
            this.dsc_menu.style.left    = this.inc_mouse_x + "px";
            this.dsc_menu.style.top     = this.inc_mouse_y + "px";
            this.dsc_menu.style.display = "block";
            return false;
        }
        alert( "Context menu: '" + str_id + "'not found" );
        return true;
    } // end of m_show


    /**
     * public function m_hide
     * hide all element given by name
     *
     * @return      nothing
    */
    this.m_hide = function()
    {
        if (    this.dsc_menu
             && this.boc_hide  ) {
            this.dsc_menu.style.display = "none";
            this.dsc_menu               = null;
        }
        this.boc_hide = true;
    } // end of m_hide


    /**
     * public function m_link
     * keep link in context menu working
     *
     * @return      bool
    */
    this.m_link = function()
    {
        this.boc_hide = false;
        return true;
    } // end of m_link


    /**
     * public function m_stop_propagation
     * stop reaching events up in DOM
     *
     * @param[in]   event   ds_event
    */
    this.m_stop_propagation = function( ds_event )
    {
        if ( !ds_event ) {
            ds_event = window.event;
        }
        if ( ds_event.stopPropagation ) {
            ds_event.stopPropagation();
        } else {
            ds_event.cancelBubble = true;
        }
    } // end of m_stop_propagation


    /**
     * private function m_get_mouse
     * get current mouse position
     *
     * @param[in]   event   ds_event    click event
     * @return      nothing
    */
    this.m_get_mouse = function( ds_event )
    {
        this.inc_mouse_x = document.all ? window.event.clientX : ds_event.clientX;
        this.inc_mouse_y = document.all ? window.event.clientY : ds_event.clientY;
    } // end of m_get_mouse


    /**
     * private function m_load_menu
     * load menu by its given id
     *
     * @param[in]   string  str_id          id of element to show
     * @return  bool
    */
    this.m_load_menu = function( str_id )
    {
        this.dsc_menu = document.getElementById( str_id );
        return (this.dsc_menu?true:false);
    } // end of m_load_menu


    /**
     * private function m_check_target
     * do NOT open menu if given event is a left click
     * and element is input field
     * 
     * @param[in]   event   ds_event        click event
     * @return      bool                    true = show menu
    */
    this.m_check_target = function ( ds_event )
    {
        // initialize some variables:
        var dsl_target;
        
        try {
        /*
            if (    ( ds_event.type.toLowerCase() == "mousedown" )
                 && (    ( ds_event.button && ds_event.button == 2 )
                      || ( ds_event.which  && ds_event.which  == 3 ) ) ) {
                return true;
            }
        */            

            // check if we have a left-click:
            if ( ds_event.type.toLowerCase() != "click" ) {
                return true;
            }
            
            // get target of click:
            dsl_target = document.all ? ds_event.srcElement : ds_event.target;
            if ( !dsl_target ) {
                return true;
            }
            
            if ( dsl_target.nodeName.toLowerCase() != "input" ) {
                return true;
            }
        } catch (e) {
            alert( "m_check_target failed!" );
        }
        return false;
    } // end of m_check_target
} // end of dsd_context_menu


/*+---------------------------------------------------------------------+*/
/*| timer object:                                                       |*/
/*+---------------------------------------------------------------------+*/
var dsg_timer = {
    inc_timeout   : 0,              /* total timeout in seconds          */
    inc_counter   : 0,              /* current timeout in seconds        */
    m_callback    : null,           /* callback function after timeout   */
    dsc_intervall : null,           /* intervall object                  */

    strc_cur_pref : "",             /* prefix string for current timeout */
    strc_cur_suff : "",             /* suffix string for current timeout */

    dsc_button    : null,           /* start/stop button                 */
    strc_btn_rdy  : "",             /* btn text, when timer is ready     */
    
    
    /**
     * public function m_init
     *
     * @param[in]   int         in_timeout      timeout in seconds
     * @param[in]   function    m_callback      function to be called
     *                                          default is reload of current page
     * @param[in]   string      str_node_pref   prefix string to current timeout
     * @param[in]   string      str_node_suff   suffix string to current timeout
     * @param[in]   object      ds_button       node, which is start/stop button
     * @param[in]   string      str_btn_rdy     button text, while timeout is ready
     * @return      nothing
    */
    m_init: function( in_timeout,    m_callback,
                      str_node_pref, str_node_suff,
                      ds_button,     str_btn_rdy )
    {
        this.inc_timeout = in_timeout;
        if ( m_callback ) {
            this.m_callback = m_callback;
        } else {
            this.m_callback = this.m_reload;
        }
        
        if ( ds_button ) {
            this.dsc_button    = ds_button;
            this.strc_btn_rdy  = str_btn_rdy;
            this.strc_cur_pref = str_node_pref;
            this.strc_cur_suff = str_node_suff;
        }
    }, // end of m_init


    /**
     * public functio m_auto_start
     * read cookie value and decide whether timer is active by default
    */
    m_auto_start: function()
    {
        if ( dsg_cookies.m_get("timer") == "1" ) {
            this.m_start();
        }
    }, // end of m_auto_start


    /**
     * public function m_start
     * start timeout and call given function after timout is gone
     *
     * @return      nothing
    */
    m_start: function()
    {
        this.inc_counter = this.inc_timeout;
        
        if ( this.dsc_button ) {
            this.dsc_button.setAttribute( "value",   this.strc_cur_pref + " "
                                                   + this.inc_counter 
                                                   + " " + this.strc_cur_suff );
        }

        this.dsc_intervall = window.setInterval( "dsg_timer.m_count_down()", 1000 );
        dsg_cookies.m_set( "timer", "1" );
    }, // end of m_start


    /**
     * public function m_stop
     * stop timeout
     *
     * @return nothing
    */
    m_stop: function()
    {
        if ( this.dsc_intervall ) {
            window.clearInterval( this.dsc_intervall );
            this.dsc_intervall = null;
        }

        if ( this.dsc_button ) {
            this.dsc_button.setAttribute( "value", this.strc_btn_rdy );
        }
        /*
        if ( this.dsc_button ) {
            this.dsc_button.innerHTML = this.strc_btn_rdy;
        }
        */
        dsg_cookies.m_set( "timer", "0" );
    }, // end of m_stop


    /**
     * public function m_swap
     * start timeout if not runing, stop it otherwise
     *
     * @return      nothing
    */
    m_swap: function()
    {
        if ( this.dsc_intervall ) {
            this.m_stop();
        } else {
            this.m_start();
        }
    }, // end of m_swap


    /**
     * private function m_count_down
     * count down seconds
     *
     * @return nothing
    */
    m_count_down: function()
    {
        this.inc_counter--;
        if ( this.dsc_button ) {
            this.dsc_button.setAttribute( "value",   this.strc_cur_pref + " "
                                                   + this.inc_counter 
                                                   + " " + this.strc_cur_suff );
        }

        if ( this.inc_counter == 0 ) {
            window.clearInterval( this.dsc_intervall );
            this.dsc_intervall = null;
            this.m_callback();

            if ( this.dsc_button ) {
                this.dsc_button.innerHTML = this.strc_btn_rdy;
            }
        }
    }, // end of m_count_down


    /**
     * private function m_reload
     * reload current page (default callback function)
     *
     * @return nothing
    */
    m_reload: function()
    {
        document.location.reload();
    } // end of m_reload
} // end of dsg_timer


/*+---------------------------------------------------------------------+*/
/*| date/time object:                                                   |*/
/*+---------------------------------------------------------------------+*/
function dsd_date() {
    /**
     * public function m_write
     * write date from epoch
     *
     * @param[in]   int     in_milliseconds
    */
    this.m_write = function( in_milliseconds )
    {
        document.write( this.m_to_string(in_milliseconds) );
    } // end of m_write


    /**
     * public function m_to_string
     * get given epoch as string
     *
     * @param[in]   int     in_milliseconds
     * @return      string
    */
    this.m_to_string = function( in_milliseconds )
    {
        var dsl_today = new Date();
        var dsl_epoch = new Date( in_milliseconds );
        var inl_hours = dsl_epoch.getHours();
        var inl_min   = dsl_epoch.getMinutes();
        var inl_sec   = dsl_epoch.getSeconds();
        var inl_day   = dsl_epoch.getDate();
        var inl_month = dsl_epoch.getMonth() + 1;
        var inl_year  = dsl_epoch.getYear();
        
        if (    inl_day   == dsl_today.getDate()
             && inl_month == dsl_today.getMonth() + 1
             && inl_year  == dsl_today.getYear()      ) {
            return   ((inl_hours < 10) ? "0"  + inl_hours : inl_hours ) + ":"
                   + ((inl_min < 10)   ? "0"  + inl_min   : inl_min   ) + ":"
                   + ((inl_sec < 10)   ? "0"  + inl_sec   : inl_sec   );
        }

        return   ((inl_day < 10)   ? "0"  + inl_day   : inl_day   ) + "."
               + ((inl_month < 10) ? "0"  + inl_month : inl_month ) + "."
               + ((inl_year < 999) ? inl_year + 1900  : inl_year  ) + " "
               + ((inl_hours < 10) ? "0"  + inl_hours : inl_hours ) + ":"
               + ((inl_min < 10)   ? "0"  + inl_min   : inl_min   ) + ":"
               + ((inl_sec < 10)   ? "0"  + inl_sec   : inl_sec   );
    } // end of m_to_string


    /**
     * public function m_from_string
     * get date object from given string
     *
     * @param[in]   string  str_date    date as string
     * @return      int                 milliseconds
     *                                  -1 in error cases
    */
    this.m_from_string = function( str_date )
    {
        // initialize some variables:
        var strrl_date;
        var dsl_today;

        // check date syntax:
        strrl_date = str_date.match(/(\d\d)[\/\.](\d\d)[\/\.](\d\d\d\d)\s(\d\d)[:](\d\d)[:](\d\d)$/);
        if ( !strrl_date ) {
            // check for only time syntax:
            strrl_date = str_date.match(/(\d\d)[:](\d\d)[:](\d\d)$/);
            if ( strrl_date ) {
                dsl_today = new Date();
                dsl_today.setHours  ( parseInt(strrl_date[1], 10) );
                dsl_today.setMinutes( parseInt(strrl_date[2], 10) );
                dsl_today.setSeconds( parseInt(strrl_date[3], 10) );
                dsl_today.setMilliseconds( 0 );
                return dsl_today;
            }
            return -1;
        }

        return new Date( parseInt(strrl_date[3], 10),     /* year    */
                         parseInt(strrl_date[2], 10) - 1, /* month   */
                         parseInt(strrl_date[1], 10),     /* day     */
                         parseInt(strrl_date[4], 10),     /* hours   */
                         parseInt(strrl_date[5], 10),     /* minutes */
                         parseInt(strrl_date[6], 10)      /* seconds */ );
    } // end of m_from_string
} // end of dsd_data


/*+---------------------------------------------------------------------+*/
/*| query parser:                                                       |*/
/*+---------------------------------------------------------------------+*/
function dsd_query() {
    this.dsc_search = new Array();
    
    /**
     * public function m_init
     * parse query from url and store it in our array
     *
     * @return  nothing
    */
    this.m_init = function()
    {
        // initialize some variables:
        var strrl_search;
        var strrl_element;
        var dsl_element;
        var inl_pos;

        if (    window.location.search           == ""
             || window.location.search.charAt(0) != "?" ) {
            return;
        }

        strrl_search = window.location.search.slice(1).split("&");
        for ( inl_pos = 0; inl_pos < strrl_search.length; inl_pos++ ) {
            strrl_element = strrl_search[inl_pos].split("=");

            // create element:
            dsl_element       = new Object();
            dsl_element.name  = strrl_element[0];
            dsl_element.value = decodeURIComponent( strrl_element[1].replace(/\+/g, "%20") );

            this.dsc_search.push( dsl_element );
        }
    } // end of m_init


    /**
     * public function m_get
     * get value from query for given name
     *
     * @param[in]   string  str_name    name of search query
     * @return      string              value of query
     *                                  "" if not found
    */
    this.m_get = function( str_name )
    {
        // initialize some variables:
        var inl_pos;
        
        for ( inl_pos = 0; inl_pos < this.dsc_search.length; inl_pos++ ) {
            if ( this.dsc_search[inl_pos].name == str_name ) {
                return this.dsc_search[inl_pos].value;
            }
        }
        return "";
    } // end of m_get


    /**
     * public function m_fill
     * fill given from with found values
     *
     * @param[in]   object  ds_form     from to be filled
     * @return      nothing
    */
    this.m_fill = function ( ds_form )
    {
        var dsl_elements;
        var inl_pos;
        var strl_value;

        if (    !ds_form
             || !ds_form.elements ) {
            return;
        }
        dsl_elements = ds_form.elements;

        for ( inl_pos = 0; inl_pos < dsl_elements.length; inl_pos++ ) {
            if ( !dsl_elements[inl_pos].name ) {
                continue;
            }

            strl_value = this.m_get( dsl_elements[inl_pos].name );
            if ( !strl_value ) {
                continue;
            }

            switch ( dsl_elements[inl_pos].type.toLowerCase() ) {
                case "text":
                case "hidden":
                    if ( !dsl_elements[inl_pos].value ) {
                        dsl_elements[inl_pos].value = strl_value;
                    }
                    break;

                case "checkbox":
                    if ( strl_value == dsl_elements[inl_pos].value ) {
                        dsl_elements[inl_pos].checked = true;
                    } else {
                        dsl_elements[inl_pos].checked = false;
                    }
                    break;
            }
        }
    } // end of m_fill
} // end of dsd_query


/*+---------------------------------------------------------------------+*/
/*| form helper:                                                        |*/
/*+---------------------------------------------------------------------+*/
function dsd_form() {
    /**
     * public function m_submit
     * submit given form
     *
     * @param[in]   object  ds_form     form
     * @return      nothing
    */
    this.m_submit = function( ds_form )
    {
        if ( ds_form ) {
            ds_form.submit();
        }
    } // end of m_submit


    /**
     * public function m_deselect_all
     * uncheck all checkboxes from given form
     *
     * @param[in]   object  ds_form     form
     * @return      nothing
    */
    this.m_deselect_all = function( ds_form )
    {
        var dsl_elements;
        var inl_pos;
        
        if (    !ds_form
             || !ds_form.elements ) {
            return;
        }
        dsl_elements = ds_form.elements;
        
        for ( inl_pos = 0; inl_pos < dsl_elements.length; inl_pos++ ) {
            if (    dsl_elements[inl_pos].type.toLowerCase() == "checkbox"
                 && dsl_elements[inl_pos].checked            == true ) {
                dsl_elements[inl_pos].checked = false;
            }
        }
    } // end of m_deselect_all


    /**
     * public function m_select_all
     * check all checkboxes from given form
     *
     * @param[in]   object  ds_form     form
     * @return      nothing
    */
    this.m_select_all = function( ds_form )
    {
        var dsl_elements;
        var inl_pos;
        
        if (    !ds_form
             || !ds_form.elements ) {
            return;
        }
        dsl_elements = ds_form.elements;
        
        for ( inl_pos = 0; inl_pos < dsl_elements.length; inl_pos++ ) {
            if (    dsl_elements[inl_pos].type.toLowerCase() == "checkbox"
                 && dsl_elements[inl_pos].checked            == false ) {
                dsl_elements[inl_pos].checked = true;
            }
        }
    } // end of m_select_all


    /**
     * public function m_swap_select
     * if one checkbox is not selected, select them all
     * other wise deselect all
     *
     * @param[in]   object  ds_form     form
     * @return      nothing
    */
    this.m_swap_select = function( ds_form )
    {
        var dsl_elements;
        var inl_pos;
        var bol_unselected_found = false;
        
        if (    !ds_form
             || !ds_form.elements ) {
            return;
        }
        dsl_elements = ds_form.elements;
        
        // select all:
        for ( inl_pos = 0; inl_pos < dsl_elements.length; inl_pos++ ) {
            if (    dsl_elements[inl_pos].type.toLowerCase() == "checkbox"
                 && dsl_elements[inl_pos].checked            == false ) {
                bol_unselected_found = true;
                dsl_elements[inl_pos].checked = true;
            }
        }
        
        // deselect all:
        if ( bol_unselected_found == false ) {
            for ( inl_pos = 0; inl_pos < dsl_elements.length; inl_pos++ ) {
                if ( dsl_elements[inl_pos].type.toLowerCase() == "checkbox" ) {
                    dsl_elements[inl_pos].checked = false;
                }
            }
        }
    } // end of m_swap_select


    /**
     * public function m_select_value
     * check input with given value
     *
     * @param[in]   object  ds_form         form
     * @param[in]   string  str_value       value
     * @param[in]   bool    bo_reset_others deselect other checkboxes?
     * @return      nothing
    */
    this.m_select_value = function( ds_form, str_value, bo_reset_others )
    {
        var dsl_elements;
        var inl_pos;

        if (    !ds_form
             || !ds_form.elements ) {
            return;
        }
        dsl_elements = ds_form.elements;

        for ( inl_pos = 0; inl_pos < dsl_elements.length; inl_pos++ ) {
            if ( dsl_elements[inl_pos].type.toLowerCase() == "checkbox" ) {
                if (    dsl_elements[inl_pos].checked == false
                     && dsl_elements[inl_pos].value   == str_value ) {
                    dsl_elements[inl_pos].checked = true;
                    if ( !bo_reset_others ) {
                        break;
                    }
                } else if (    bo_reset_others
                            && dsl_elements[inl_pos].checked == true
                            && dsl_elements[inl_pos].value   != str_value  ) {
                    dsl_elements[inl_pos].checked = false;
                }
            }
        }
    } // end of m_select_value


    /**
     * public function m_is_selected
     * check if input field is checked
     *
     * @param[in]   object  ds_form     form
     * @param[in]   string  str_name    name of input field
     * @return      bool                true = is selected
    */
    this.m_is_selected = function( ds_form, str_name )
    {
        var dsl_elements;
        var inl_pos;

        if (    !ds_form
             || !ds_form.elements ) {
            return false;
        }
        dsl_elements = ds_form.elements;

        for ( inl_pos = 0; inl_pos < dsl_elements.length; inl_pos++ ) {
            if (    dsl_elements[inl_pos].type.toLowerCase() == "checkbox"
                 && dsl_elements[inl_pos].name               == str_name  ) {
                return dsl_elements[inl_pos].checked;
            }
        }
        return false;
    } // end of m_is_selected


    /**
     * public function m_get_value
     * get input field with given name to given value
     *
     * @param[in]   object  ds_form     form
     * @param[in]   string  str_name    name of input field
     * @return      string              value
    */
    this.m_get_value = function( ds_form, str_name )
    {
        var dsl_elements;
        var inl_pos;

        if (    !ds_form
             || !ds_form.elements ) {
            return;
        }
        dsl_elements = ds_form.elements;

        for ( inl_pos = 0; inl_pos < dsl_elements.length; inl_pos++ ) {
            if ( dsl_elements[inl_pos].name != str_name ) {
                continue;
            }

            switch ( dsl_elements[inl_pos].type.toLowerCase() ) {
                case "text":
                case "hidden":
                case "checkbox":
                    return dsl_elements[inl_pos].value;
            }
        }
    } // end of m_get_value


    /**
     * public function m_set_value
     * set input field with given name to given value
     *
     * @param[in]   object  ds_form     form
     * @param[in]   string  str_name    name of input field
     * @param[in]   string  str_value   new value
     * @return      nothing
    */
    this.m_set_value = function( ds_form, str_name, str_value )
    {
        var dsl_elements;
        var inl_pos;

        if (    !ds_form
             || !ds_form.elements ) {
            return;
        }
        dsl_elements = ds_form.elements;

        for ( inl_pos = 0; inl_pos < dsl_elements.length; inl_pos++ ) {
            if ( dsl_elements[inl_pos].name != str_name ) {
                continue;
            }

            switch ( dsl_elements[inl_pos].type.toLowerCase() ) {
                case "text":
                case "hidden":
                    dsl_elements[inl_pos].value = str_value;
                    break;

                case "checkbox":
                    if ( dsl_elements[inl_pos].value == str_value ) {
                        dsl_elements[inl_pos].checked = true;
                    } else {
                        dsl_elements[inl_pos].checked = false;
                    }
                    break;
            }
        }
    } // end of m_set_value


    /**
     * public function m_clear_value
     * clear input field with given name
     *
     * @param[in]   object  ds_form     form
     * @param[in]   string  str_name    name of input field
     * @return      nothing
    */
    this.m_clear_value = function( ds_form, str_name )
    {
        this.m_set_value( ds_form, str_name, "" );
    } // end of m_clear_value


    /**
     * public function m_enable
     * search submit button with given value
     * and enable it
     *
     * @param[in]   object  ds_form     form
     * @param[in]   string  str_value   value of input field
     * @return      nothing
    */
    this.m_enable = function( ds_form, str_value )
    {
        var dsl_elements;
        var inl_pos;

        if (    !ds_form
             || !ds_form.elements ) {
            return;
        }
        dsl_elements = ds_form.elements;

        for ( inl_pos = 0; inl_pos < dsl_elements.length; inl_pos++ ) {
            if (    dsl_elements[inl_pos].type.toLowerCase() == "submit"
                 && dsl_elements[inl_pos].value              == str_value ) {
                dsl_elements[inl_pos].disabled = false;
            }
        }
    } // end of m_enable


    /**
     * public function m_disable
     * search submit button with given value
     * and disable it
     *
     * @param[in]   object  ds_form     form
     * @param[in]   string  str_value   value of input field
     * @return      nothing
    */
    this.m_disable = function( ds_form, str_value )
    {
        var dsl_elements;
        var inl_pos;

        if (    !ds_form
             || !ds_form.elements ) {
            return;
        }
        dsl_elements = ds_form.elements;

        for ( inl_pos = 0; inl_pos < dsl_elements.length; inl_pos++ ) {
            var type = dsl_elements[inl_pos].type.toLowerCase();
            var value = dsl_elements[inl_pos].value.toLowerCase();
            var str = str_value.toLowerCase();
            if (    dsl_elements[inl_pos].type.toLowerCase() == "submit"
                 && dsl_elements[inl_pos].value.toLowerCase() == str_value.toLowerCase() ) {
                dsl_elements[inl_pos].disabled = true;
            }
        }
    } // end of m_disable
}; // end of dsd_form

/*+---------------------------------------------------------------------+*/
/*| table helper:                                                       |*/
/*+---------------------------------------------------------------------+*/
function dsd_table() {
    this.dsc_table  = null;             /* table node                    */
    this.inc_rows   = 0;                /* number of rows                */
    this.inc_cols   = 0;                /* number of columns             */
    this.inc_height = 0;                /* height of table in pixel      */
    this.dsc_hidden = new Array();      /* list of hidden columns        */

    /**
     * public function m_init
     *
     * @param[in]   string  str_id      id of current table
     * @return      bool                true = success
    */
    this.m_init = function( str_id )
    {
        var inl_pos;

        this.dsc_table = document.getElementById( str_id );

        if ( this.dsc_table ) {
            this.inc_rows = this.dsc_table.rows.length;
            if ( this.inc_rows > 0 ) {
                this.inc_cols = this.dsc_table.rows[0].cells.length;
            }

            this.inc_height = this.dsc_table.offsetHeight;
        }

        return (this.dsc_table?true:false);
    } // end of m_init


    /**
     * public function m_count_rows
     * get number of current rows
     *
     * @return      int                 number of current rows
    */
    this.m_count_rows = function()
    {
        return this.inc_rows;
    } // end of m_count_rows


    /**
     * public function m_count_cols
     * get number of current columns
     *
     * @return      int                 number of current columns
    */
    this.m_count_cols = function()
    {
        return this.inc_cols;
    } // end of m_count_cols


    /**
     * public function m_get_row
     * get row by given row index
     *
     * @param[in]   int     in_row      index of row
     * @return      object              selected row
     *                                  null in error cases
    */
    this.m_get_row = function( in_row )
    {
        if (    in_row < 0
             || in_row >= this.inc_rows ) {
            return null;
        }
        
        return this.dsc_table.rows[in_row];
    } // end of m_get_row


    /**
     * public function m_first_row
     * get first row
     *
     * @return      object              first row
     *                                  null in error cases
    */
    this.m_first_row = function()
    {
        if ( this.inc_rows < 1 ) {
            return null;
        }
        
        return this.dsc_table.rows[0];
    } // end of m_first_row


    /**
     * public function m_last_row
     * get last row
     *
     * @return      object              last row
     *                                  null in error cases
    */
    this.m_last_row = function()
    {
        if ( this.inc_rows < 1 ) {
            return null;
        }
        
        return this.dsc_table.rows[this.inc_rows - 1];
    } // end of m_last_row


    /**
     * public function m_get_cell
     * get cell by given row and col index
     *
     * @param[in]   int     in_row      index of row
     * @param[in]   int     in_col      index of column
     * @return      object              selected cell
     *                                  null in error cases
    */
    this.m_get_cell = function( in_row, in_col )
    {
        if (    in_row < 0
             || in_row >= this.inc_rows
             || in_col < 0
             || in_col >= this.inc_cols ) {
            return null;
        }
        
        return this.dsc_table.rows[in_row].cells[in_col];
    } // end of m_get_cell


    /**
     * public function m_first_cell
     * get first cell from given row
     *
     * @param[in]   int     in_row      index of row
     * @return      object              selected cell
     *                                  null in error cases
    */
    this.m_first_cell = function( in_row )
    {
        return this.m_get_cell( in_row, 0 );
    } // end of m_first_cell


    /**
     * public function m_last_cell
     * get last cell from given row
     *
     * @param[in]   int     in_row      index of row
     * @return      object              selected cell
     *                                  null in error cases
    */
    this.m_last_cell = function( in_row )
    {
        return this.m_get_cell( in_row, this.inc_cols - 1 );
    } // end of m_last_cell


    /**
     * public function m_get_row_attr
     * get attribute from row by given row index
     *
     * @param[in]   int     in_row      index of row
     * @param[in]   string  str_attr    attribute
     * @return      string              value of attribute
     *                                  "" in error cases
    */
    this.m_get_row_attr = function( in_row, str_attr )
    {
        // initialize some variables:
        var dsl_row;

        dsl_row = this.m_get_row( in_row );
        if ( !dsl_row ) {
            return "";
        }

        return dsl_row.getAttribute( str_attr );
    } // end of m_get_row_attr


    /**
     * public function m_first_row_attr
     * get first row attribute
     *
     * @param[in]   string  str_attr    attribute
     * @return      string              value of attribute
     *                                  "" in error cases
    */
    this.m_first_row_attr = function( str_attr )
    {
        // initialize some variables:
        var dsl_row;

        dsl_row = this.m_first_row();
        if ( !dsl_row ) {
            return "";
        }

        return dsl_row.getAttribute( str_attr );
    } // end of m_first_row_attr


    /**
     * public function m_last_row_attr
     * get last row attribute
     *
     * @param[in]   string  str_attr    attribute
     * @return      string              value of attribute
     *                                  "" in error cases
    */
    this.m_last_row_attr = function( str_attr )
    {
        // initialize some variables:
        var dsl_row;

        dsl_row = this.m_last_row();
        if ( !dsl_row ) {
            return "";
        }

        return dsl_row.getAttribute( str_attr );
    } // end of m_last_row_attr


    /**
     * public function m_get_cell_attr
     * get attribute from cell by given row and col index
     *
     * @param[in]   int     in_row      index of row
     * @param[in]   int     in_col      index of column
     * @param[in]   string  str_attr    attribute
     * @return      string              value of attribute
     *                                  "" in error cases
    */
    this.m_get_cell_attr = function( in_row, in_col, str_attr )
    {
        // initialize some variables:
        var dsl_cell;

        dsl_cell = this.m_get_cell( in_row, in_col );
        if ( !dsl_cell ) {
            return "";
        }

        return dsl_cell.getAttribute( str_attr );
    } // end of m_get_cell_attr


    /**
     * public function m_remove_row
     * delete a given row from table
     *
     * @param[in]   int     in_row      index of row
     * @return      bool                true = success
    */
    this.m_remove_row = function( in_row )
    {
        var dsl_row;
        
        dsl_row = this.m_get_row( in_row );
        if ( dsl_row ) {
            this.inc_rows   --;
            this.inc_height -= dsl_row.offsetHeight;
            dsl_row.parentNode.removeChild( dsl_row );
        }
        return (dsl_row?true:false);
    } // end of m_remove_row


    /**
     * public function m_row_auto_fit
     * remove rows, until content will fit into page
     * without scrolling
     *
     * @param[in]   bool    bo_from_top     if true, we will remove rows
     *                                      from top, otherwise from botton
     * @return      int                     number of removed lines
     *                                      negativ in error cases
    */
    this.m_row_auto_fit = function( bo_from_top )
    {
        // initialize some variables:
        var inl_avail_height;               // available height
        var inl_cur_height;                 // current height
        var inl_tmp_height;                 // temp height
        var inl_rm_rows;                    // number of removed rows
        var dsl_parent;                     // last parent node before body
        var bol_ret;                        // return from remove row call

        // get relative parent node to body element
        dsl_parent = this.dsc_table;
        while (    dsl_parent.parentNode
                && dsl_parent.parentNode != document.body ) {
            dsl_parent = dsl_parent.parentNode;
        }
        if ( dsl_parent.parentNode != document.body ) {
            return -1;
        }

        // calculate current and available height:
        // (see https://stackoverflow.com/questions/1145850/how-to-get-height-of-entire-document-with-javascript)
        var body = document.body, html = document.documentElement;
        inl_cur_height   = Math.max( dsl_parent.offsetHeight, dsl_parent.scrollHeight );
        inl_avail_height = Math.max( body.scrollHeight, body.offsetHeight, 
                                     html.clientHeight, html.scrollHeight, html.offsetHeight );
        // remove height of parts, that are not included in "parent" from "available height" 
        for ( inl_pos = 0; inl_pos < document.body.childNodes.length; inl_pos++ ) {
            if (    document.body.childNodes[inl_pos].offsetHeight
                 && document.body.childNodes[inl_pos] != dsl_parent ) {
                inl_avail_height -= document.body.childNodes[inl_pos].offsetHeight;
            }
        }

        // remove rows if needed:
        inl_rm_rows = 0;
        while ( inl_cur_height > inl_avail_height ) {
            inl_tmp_height = this.inc_height;

            if ( bo_from_top ) {
                bol_ret = this.m_remove_row( 1 ); // keep header line
            } else {
                bol_ret = this.m_remove_row( this.inc_rows - 1 );
            }
            if ( !bol_ret ) {
                return inl_rm_rows;
            }

            inl_rm_rows++;
            inl_cur_height -= (inl_tmp_height - this.inc_height);
        }
        
        return inl_rm_rows;
    } // end of m_row_auto_fit


    /**
     * public function m_col_auto_hide
     * auto hide cols, which are saved in cookie
    */
    this.m_col_auto_hide = function()
    {
        var strrl_hide;
        var inl_pos;
        var strl_page  = document.location.pathname.substr( document.location.pathname.lastIndexOf('/') + 1 );
        var strl_value = dsg_cookies.m_get( "hide-" + strl_page );
        if ( ! strl_value ) {
            return;
        }

        strrl_hide = strl_value.split(",");
        
        for ( inl_pos = 0; inl_pos < strrl_hide.length; inl_pos++ ) {
            this.m_hide_col( parseInt(strrl_hide[inl_pos], 10) );
        }
    } // end of m_col_auto_hide


    /**
     * public function m_get_col_name
     * get name of column (means content of first element)
     *
     * @param[in]   int     in_col      column index
     * @return      string              name of column
    */
    this.m_get_col_name = function( in_col )
    {
        var dsl_cell = this.m_get_cell( 0, in_col );
        if (    !dsl_cell
             || !dsl_cell.firstChild
             || !dsl_cell.firstChild.nodeValue ) {
            return "";
        }
        return dsl_cell.firstChild.nodeValue;
    } // end of m_get_col_name


    /**
     * public function m_get_col_names
     * get all name of columns (means content of first element)
     *
     * @return      array               array of names
    */
    this.m_get_col_names = function()
    {
        var dsl_names = new Array();
        var strl_name;
        var inl_pos;

        for ( inl_pos = 0; inl_pos < this.inc_cols; inl_pos++ ) {
            strl_name = this.m_get_col_name( inl_pos );
            dsl_names.push( strl_name );
        }
        return dsl_names;
    } // end of m_get_col_name
     

    /**
     * public function m_hide_col
     * hide given column
     *
     * @param[in]   int     in_col      column index
     * @return      nothing
    */
    this.m_hide_col = function( in_col )
    {
        if ( in_col >= this.inc_cols ) {
            return;
        }
        this.m_add_hidden_col( in_col );
        for ( var inl_pos = 0; inl_pos < this.inc_rows; inl_pos++ ) {
            this.dsc_table.rows[inl_pos].cells[in_col].style.display = "none";
        }
    } // end of m_hide_col


    /**
     * public function m_show_col
     * show given column
     *
     * @param[in]   int     in_col      column index
     * @return      nothing
    */
    this.m_show_col = function( in_col )
    {
        if ( in_col >= this.inc_cols ) {
            return;
        }
        this.m_del_hidden_col( in_col );
        for ( var inl_pos = 0; inl_pos < this.inc_rows; inl_pos++ ) {
            this.dsc_table.rows[inl_pos].cells[in_col].style.display = "";
        }
    } // end of m_show_col


    /**
     * public function m_swap_col
     * show given column when is it not visible, otherwise hide it
     *
     * @param[in]   int     in_col      column index
     * @return      nothing
    */
    this.m_swap_col = function( in_col )
    {
        var strl_disp;

        if (    in_col >= this.inc_cols
             || this.inc_rows < 1       ) {
            return;
        }
        
        if ( this.m_is_visible( this.dsc_table.rows[0].cells[in_col] ) == true ) {
            strl_disp = "none";
            this.m_add_hidden_col( in_col );
        } else {
            strl_disp = "";
            this.m_del_hidden_col( in_col );
        }

        for ( var inl_pos = 0; inl_pos < this.inc_rows; inl_pos++ ) {
            this.dsc_table.rows[inl_pos].cells[in_col].style.display = strl_disp;
        }
    } // end of m_swap_col


    /**
     * public function m_col_visible
     * is given column visible
     *
     * @param[in]   int     in_col      column index
     * @return      bool
    */
    this.m_col_visible = function( in_col )
    {
        var dsl_cell = this.m_get_cell( 0, in_col );
        return (dsl_cell ? this.m_is_visible( dsl_cell ) : false);
    } // end of m_col_visible


    /**
     * private function m_get_style
     *
     * @param[in]   object      ds_element
     * @param[in]   string      str_prop
     * @return      string                      style prop value
    */
    this.m_get_style = function( ds_element, str_prop )
    {
        if ( ds_element.currentStyle ) {
            return ds_element.currentStyle[str_prop];
        } else if ( document.defaultView ) {
            if ( document.defaultView.getComputedStyle ) {
                return document.defaultView.getComputedStyle( ds_element, "" )[str_prop];
            }
        }
        return ds_element.style[str_prop];
    } // end of m_get_style


    /**
     * private function m_is_visible
     * decide whether given element is visible or not
     *
     * @param[in]   object      ds_element
     * @return      bool
    */
    this.m_is_visible = function( ds_element )
    {
        var strl_disp = this.m_get_style( ds_element, "display" );
        if (    strl_disp == ""
             || strl_disp == "none" ) {
            return false;
        }
        return true;
    } // end of m_is_visible


    /**
     * private function m_add_hidden_col
     * add hidden column to our list
     *
     * @param[in]   int     in_col
     * @return nothing
    */
    this.m_add_hidden_col = function( in_col )
    {
        this.dsc_hidden.push( in_col );
        this.m_save_hidden_cols();
    } // end of m_add_hidden_col


    /**
     * private function m_del_hidden_col
     * remove hidden column from our list
     *
     * @param[in]   int     in_col
     * @return nothing
    */
    this.m_del_hidden_col = function( in_col )
    {
        for ( inl_pos = 0; inl_pos < this.dsc_hidden.length; inl_pos++ ) {
            if ( this.dsc_hidden[inl_pos] == in_col ) {
                this.dsc_hidden.splice( inl_pos, 1 );
                break;
            }
        }
        this.m_save_hidden_cols();
    } // end of m_del_hidden_col


    /**
     * private function m_save_hidden_cols
     * save hidden cols as cookie per page
     *
     * @return nothing
    */
    this.m_save_hidden_cols = function()
    {
        var strl_page = document.location.pathname.substr( document.location.pathname.lastIndexOf('/') + 1 );
        dsg_cookies.m_set( "hide-" + strl_page,
                           this.dsc_hidden.toString() );
    } // end of m_save_hidden_cols
} // end of dsd_table 


/*+---------------------------------------------------------------------+*/
/*| sort class:                                                         |*/
/*+---------------------------------------------------------------------+*/
var dsg_sort = {
    dsc_table: null,

    /**
     * public function m_init
     * initialize sorter class
     *
     * @param[in]   object  ds_table    table
     * @return      bool
    */
    m_init: function( ds_table )
    {
        // initialize some variables:
        var inl_col;
        var dsl_heads;

        // get first header lines of table:
        if (    !ds_table
             || !ds_table.tHead
             || !ds_table.tHead.rows
             || !ds_table.tHead.rows[0]
             || !ds_table.tHead.rows[0].cells ) {
            alert( "dsg_sort.m_init() failed" );
            return false;
        }
        dsl_heads = ds_table.tHead.rows[0].cells;
        if ( dsl_heads.length < 1 ) {
            alert( "dsg_sort.m_init() failed - dsl_heads.length < 1" );
            return false;
        }
        this.dsc_table = ds_table;

        for ( inl_col = 0; inl_col < dsl_heads.length; inl_col++ ) {
            // don't make empty rows sortable:
            if ( !dsl_heads[inl_col].innerHTML ) {
                continue;
            }

            // guess type of column content:
            dsl_heads[inl_col].m_sort = this.m_guess_type( inl_col );

            // save column index and table body:
            dsl_heads[inl_col].inc_column = inl_col;
            dsl_heads[inl_col].dsc_body   = ds_table.tBodies[0];

            // add click event to table head:
            this.m_add_event( dsl_heads[inl_col], "click", this.m_cb_sort );
        }
    }, // end of m_init


    /**
     * public function m_sort_column
     * sort given column number
     *
     * @param[in]   int     in_column
     * @return      nothing
    */
    m_sort_column: function ( in_column )
    {
        // initialize some variables:
        var dsl_column;

        try {
            dsl_column = this.dsc_table.tHead.rows[0].cells[in_column];
        } catch(e) {
            return;
        }
        this.m_sort_col( dsl_column );
    }, // end of m_sort_column


    /**
     * private function m_cb_sort
     * sort function
     *
     * @param[in]   event ds_event
     * @return      nothing
    */
    m_cb_sort: function( ds_event )
    {
        // initialize some variables:
        var dsl_object;

        //---------------------------------------
        // get working object:
        //---------------------------------------
        if ( !ds_event ) {
            ds_event = window.event;
        }
        if ( ds_event.srcElement ) {
            dsl_object = ds_event.srcElement;            
        } else {
            dsl_object = this;
        }
        if ( !dsl_object ) {
            return;
        }
        
        dsg_sort.m_sort_col( dsl_object );
    }, // end of m_cb_sort


    /**
     * private function m_sort_col
     * sort given column
     *
     * @param[in]   object  ds_column
     * @return      nothing
    */
    m_sort_col: function( ds_column )
    {
        // initialize some variables:
        var dslr_rows;
        var dslr_sort;
        var inl_count;
        var strl_sorted;
        var dsl_childs;
        
        if ( !ds_column.dsc_body ) {
            if (    ds_column.parentNode
                 && ds_column.parentNode.dsc_body ) {
                ds_column = ds_column.parentNode;
            } else {
                return;
            }
        }

        //---------------------------------------
        // remove old arrow:
        //--------------------------------------- 
        this.m_remove_arrow();

        //---------------------------------------
        // check if this row is already sorted:
        //---------------------------------------
        strl_sorted = ds_column.getAttribute("sorted");
        if ( strl_sorted ) {
            if ( strl_sorted == "down" ) {
                this.m_reverse( ds_column.dsc_body );
                ds_column.setAttribute( "sorted", "up" );
                this.m_add_arrow( ds_column, false );
                return;
            } else if ( strl_sorted == "up" ) {
                this.m_reverse( ds_column.dsc_body );
                ds_column.setAttribute( "sorted", "down" );
                this.m_add_arrow( ds_column, true );
                return;
            }
        }

        //---------------------------------------
        // remove all older sorted attributes:
        //---------------------------------------
        dsl_childs = ds_column.parentNode.childNodes;
        for ( inl_count = 0; inl_count < dsl_childs.length; inl_count++ ) {
            try {
                dsl_childs[inl_count].removeAttribute("sorted");
            } catch(e){}
        }

        //---------------------------------------
        // add new arrow:
        //---------------------------------------
        this.m_add_arrow( ds_column, true );

        //---------------------------------------
        // get array of rows:
        //---------------------------------------
        dslr_rows = ds_column.dsc_body.rows;
        dslr_sort = new Array();
        for ( inl_count = 0; inl_count < dslr_rows.length; inl_count++ ) {
            dslr_sort.push( [ this.m_get_inner(dslr_rows[inl_count].cells[ds_column.inc_column]),
                              dslr_rows[inl_count]] );
        }

        //---------------------------------------
        // do the sort:
        //---------------------------------------
        dslr_sort.sort( ds_column.m_sort );

        //---------------------------------------
        // change view table:
        //---------------------------------------
        for ( inl_count = 0; inl_count < dslr_sort.length; inl_count++ ) {
            ds_column.dsc_body.appendChild( dslr_sort[inl_count][1] );
        }

        //---------------------------------------
        // set sorted attribute:
        //---------------------------------------
        ds_column.setAttribute( "sorted", "down" );
    }, // end of m_sort_col


    /**
     * private function m_reverse
     * reverse order in a already sorted row
     *
     * @param[in]   object  ds_tbody    table body to be reversed
     * @return      nothing
    */
    m_reverse: function( ds_tbody )
    {
        // initialize some variables:
        var inl_count = 0;
        var dsl_rows  = new Array();

        for ( inl_count = 0; inl_count < ds_tbody.rows.length; inl_count++ ) {
            dsl_rows.push( ds_tbody.rows[inl_count] );
        }
        
        for ( inl_count = dsl_rows.length - 1; inl_count >= 0; inl_count-- ) {
            ds_tbody.appendChild( dsl_rows[inl_count] );
        }
    }, // end of m_reverse


    /**
     * private function m_sort_alpha
     * compare two given strings
     *
     * @param[in]   object  dsl_o1
     * @param[in]   object  dsl_o2
     * @return      int
    */
    m_sort_alpha: function( dsl_o1, dsl_o2 )
    {
        if ( dsl_o1[0] == dsl_o2[0] ) {
            return 0;
        }
        if ( dsl_o1[0] < dsl_o2[0] ) {
            return 1;
        }
        return -1;
    }, // end if m_sort_alpha


    /**
     * private function m_sort_numeric
     * compare two given strings as numbers
     *
     * @param[in]   object  dsl_o1
     * @param[in]   object  dsl_o2
     * @return      int
    */
    m_sort_numeric: function( dsl_o1, dsl_o2 )
    {
        // initialize some variables:
        var fll_1;
        var fll_2;
        
        fll_1 = parseFloat( dsl_o1[0].replace(/[^0-9.-]/g,'') );
        if ( isNaN(fll_1) ) {
            fll_1 = 0;
        }
        fll_2 = parseFloat( dsl_o2[0].replace(/[^0-9.-]/g,'') );
        if ( isNaN(fll_2) ) {
            fll_2 = 0;
        }
        return (fll_1 - fll_2);
    }, // end of m_sort_numeric


    /**
     * private function m_sort_date
     * compare two given strings as dates
     *
     * @param[in]   object  dsl_o1
     * @param[in]   object  dsl_o2
     * @return      int
    */
    m_sort_date: function( dsl_o1, dsl_o2 )
    {
        // initialize some variables:
        var inl_1;
        var inl_2;
        
        inl_1 = dsg_date.m_from_string( dsl_o1[0] );
        if ( inl_1 < 0 ) {
            inl_1 = 0;
        }
        inl_2 = dsg_date.m_from_string( dsl_o2[0] );
        if ( inl_2 < 0 ) {
            inl_2 = 0;
        }
        return ( inl_1 - inl_2 );
    }, // end of m_sort_date


    /**
     * private function m_get_inner
     * get full content of given node as text
     * strips leading and trailing whitespaces
     *
     * @param[in]   object  ds_node     current node
     * @return      string              content as string
    */
    m_get_inner: function( ds_node )
    {
        // initialize some variables:
        var inl_count;
        var strl_text;
        
        if ( !ds_node ) {
            return "";
        }
        switch ( ds_node.nodeType ) {
            case 3:
            case 4:
                return ds_node.nodeValue.replace(/^\s+|\s+$/g, '');
            case 1:
            case 11:
                strl_text = "";
                for ( inl_count = 0; inl_count < ds_node.childNodes.length; inl_count++ ) {
                    strl_text += this.m_get_inner( ds_node.childNodes[inl_count] );
                }
                return strl_text.replace(/^\s+|\s+$/g, '');
            default:
                return "";
        }
    }, // end of m_get_inner


    /**
     * private function m_is_numeric
     * check if given string is a number
     *
     * @param[in]   string  str_text
     * @return      bool
    */
    m_is_numeric: function( str_text )
    {
        if (    (str_text - 0) != str_text 
             || str_text.length < 1 ) {
            return false;
        }
        return true;
    }, // end of m_is_numeric


    /**
     * private function m_is_date
     * check if given string is a date
     *
     * @param[in]   string  str_text
     * @return      bool
    */
    m_is_date: function( str_text )
    {
        return ( dsg_date.m_from_string( str_text ) > -1? true:false );
    }, // end of m_is_date


    /**
     * private function m_add_event
     * add event to given element
     *
     * @param[in]   object      ds_element  element
     * @param[in]   string      str_name    name of event ("click" instead of "onclick")
     * @param[in]   function    ml_func     event function to be called
     * @return      nothing
    */
    m_add_event: function( ds_element, str_name, ml_func )
    {
        if ( ds_element.attachEvent ) {
            // msie, opera
            ds_element.attachEvent( "on" + str_name, ml_func );
        } else if ( ds_element.addEventListener ) {
            // mozilla
            ds_element.addEventListener( str_name, ml_func, true );
        } else {
            alert( "dsg_sort.m_add_event failed" );
        }
    }, // end of m_add_event


    /**
     * private function m_add_arrow
     * add arrow to given element
     *
     * @param[in]   object  ds_element      element to add
     * @param[in]   bool    bo_down         arrow down
     * @return      nothing
    */
    m_add_arrow: function( ds_element, bo_down )
    {
        // initialize some variables:
        var dsl_arrow;
        
        dsl_arrow = document.createElement("span");
        if ( bo_down ) {
            dsl_arrow.innerHTML = "&nbsp;&#x25BC;"
        } else {
            dsl_arrow.innerHTML = "&nbsp;&#x25B2;"
        }
        dsl_arrow.id = "sort_arrow";
        ds_element.appendChild( dsl_arrow );
    }, // end of m_add_arrow


    /**
     * private function m_remove_arrow
     * remove arrow
     *
     * @return  nothing
    */
    m_remove_arrow: function()
    {
        // initialize some variables:
        var dsl_arrow;

        dsl_arrow = document.getElementById("sort_arrow");
        if ( dsl_arrow ) {
            dsl_arrow.parentNode.removeChild( dsl_arrow );
        }
    }, // end of m_remove_arrow


    /**
     * private function m_guess_type
     * guess type of given table column number
     *
     * @param[in]   int     in_col      number of column
     * @return      func                sort function
    */
    m_guess_type: function( in_col )
    {
        // initialize some variables:
        var inl_count;
        var strl_content;
        var dsl_date;
        
        // loop through lines:
        for ( inl_count = 0; inl_count < this.dsc_table.tBodies[0].rows.length; inl_count++ ) {
            // get line content:
            strl_content = this.m_get_inner( this.dsc_table.tBodies[0].rows[inl_count].cells[in_col] );
            if (    !strl_content
                 || strl_content.length < 1 ) {
                continue;
            }
            
            // check if content is numeric:
            if ( this.m_is_numeric( strl_content ) == true ) {
                return this.m_sort_numeric;
            }
            
            // check for date:
            else if ( this.m_is_date( strl_content ) == true ) {
                return this.m_sort_date;
            }

            // sort alphabetical:
            else {
                return this.m_sort_alpha;
            }
        }        
        
        return this.m_sort_alpha;
    } // end of m_guess_type
} // end of dsg_sort

