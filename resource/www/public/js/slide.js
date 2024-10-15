/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|    slide.js                                                         |*/
/*|       a javascript library that creates a slide in window with      |*/
/*|       different content (for example a progress bar)                |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|    Michael Jakobs, 18.03.2009                                       |*/
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

var ds_interval = null;

/**
 * function m_progress_start
 * show a progress window that blocks browser
*/
function m_progress_start( str_title, str_text )
{
    var ds_content  = null;
    var ds_bar      = null;
    var ds_text     = null;
    var ds_attr     = null;

    //-------------------------------------------
    // check incomming data:
    //-------------------------------------------
    if ( !str_title ) {
        str_title = "";
    }
    if ( !str_text ) {
        str_text = "";
    }


    //-------------------------------------------
    // create progress bar:
    //-------------------------------------------
    ds_content = document.createElement("div");
	ds_attr    = document.createAttribute("class");
	ds_attr.nodeValue                = "sl_progress";
	ds_content.id                    = "sl_progress";
    ds_content.setAttributeNode(ds_attr);

    
    //-------------------------------------------
    // insert moving span:
    //-------------------------------------------
    ds_bar  = document.createElement("span");
	ds_attr = document.createAttribute("class");
	ds_attr.nodeValue                = "sl_pbar";
	ds_bar.id                        = "sl_pbar";
    ds_bar.style.position            = "absolute";
    ds_bar.setAttributeNode(ds_attr);
    ds_content.appendChild( ds_bar );
    

    //-------------------------------------------
    // insert progress text field
    //-------------------------------------------
    ds_text = document.createElement("span");
    ds_attr = document.createAttribute("class");
    ds_attr.nodeValue                = "sl_ptext";
    ds_text.id                       = "sl_ptext";
    ds_text.style.position           = "absolute";
    ds_text.setAttributeNode(ds_attr);
    ds_content.appendChild( ds_text );


    //-------------------------------------------
    // create window:
    //-------------------------------------------
    m_slide_start( false, str_title, ds_content, str_text );

    //-------------------------------------------
    // do the movement:
    //-------------------------------------------
    ds_interval = window.setInterval("m_move()", 5 );
} // end of m_progress_start


/**
 * function m_progress_stop()
 * stop progress bar
*/
function m_progress_stop()
{
    //-------------------------------------------
    // stop movement:
    //-------------------------------------------
    window.clearInterval(ds_interval);

    //-------------------------------------------
    // remove window:
    //-------------------------------------------
    m_slide_stop();
} // end of m_progress_stop


/**
 * function m_set_title
 * set title of slide window
 *
 * @param[in]   string      str_title
*/
function m_set_title( str_title )
{
    var ds_title = null;

    ds_title = document.getElementById("sl_title");
    if ( ds_title && str_title ) {
        ds_title.innerHTML = str_title;
    }
} // end of m_set_title


/**
 * function m_set_text
 * set text of slide window
 *
 * @param[in]   string  str_text
*/
function m_set_text( str_text )
{
    var ds_text = null;

    ds_text = document.getElementById("sl_text");
    if ( ds_text && str_text ) {
        ds_text.innerHTML = str_text;
    }
} // end of m_set_text


/**
 * function m_set_progress
 * set progress in %
 *
 * @param[in]   int     in_progress
*/
function m_set_progress( in_progress )
{
    var ds_progress  = null;    // progress bar object
    var ds_bar       = null;    // moving bar object
    var ds_text      = null;    // text bar object
    var in_pro_width = 0;       // width of progress
    var in_bar_width = 0;       // width of moving bar

    //-------------------------------------------
    // check incomming data:
    //-------------------------------------------
    if (    in_progress < 0
         || in_progress > 100 ) {
        return;
    }


/*
    //-------------------------------------------
    // progress of 100% means stop:
    //-------------------------------------------
    if ( in_progress == 100 ) {
        return m_progress_stop();
    }    
*/


    //-------------------------------------------
    // get the progress bar objects:
    //-------------------------------------------
    ds_progress = document.getElementById("sl_progress");
    ds_bar      = document.getElementById("sl_pbar");
    ds_text     = document.getElementById("sl_ptext");
    if ( !ds_bar || !ds_progress ) {
        return;
    }

    //-------------------------------------------
    // stop movement if running:
    //-------------------------------------------
    if ( ds_interval ) {
        window.clearInterval( ds_interval );
        ds_interval = null;
        ds_bar.style.marginLeft = "0px";
    }

    in_pro_width = parseInt( m_get_style(ds_progress).width );
    in_bar_width = in_progress * in_pro_width / 100;

    ds_bar.style.width = in_bar_width + "px";
    ds_text.innerHTML  = in_progress +"%";
} // end of m_set_progress


/**
 * function m_slide_start
 * show an 'window' that blocks browser
 *
 * @param[in]   bool    bo_show_close       show a close button?
 * @param[in]   string  str_title           title of 'window'
 * @param[in]   object  ds_object           object to show in 'window'
 * @param[in]   string  str_text            text in 'window'
*/
function m_slide_start( bo_show_close, str_title, ds_object, str_text )
{
    var ds_body       = document.body;
    var ds_back       = null;
    var ds_front      = null;
    var ds_corner     = null;
    var ds_button     = null;
    var ds_title      = null;
    var ds_text       = null;
    var ds_progress   = null;
    var ds_attr       = null;
    var ds_corner     = null;
    var ds_fill       = null;
    var in_width      = 0;
    var in_height     = 0;
    var in_bor_size   = 0;
    var in_own_width  = 0;
    var in_own_height = 0;

    if ( !ds_body ) {
        return;
    }

    //-------------------------------------------
    // create a transparent div element 
    // over hole page:
    //-------------------------------------------
	ds_back = document.createElement("div");
	ds_attr = document.createAttribute("class");
    ds_back.id                       = "sl_background";
	ds_attr.nodeValue                = "sl_background";
    ds_back.style.zIndex             = 100000;
    if ( ds_body.style.zIndex ) {
       ds_back.style.zIndex         += ds_body.style.zIndex; 
    }
    ds_back.style.position           = "absolute";
    ds_back.style.top                = "0px";
    ds_back.style.left               = "0px";
    ds_back.style.width              = "100%";
    ds_back.style.height             = "100%";
    m_opacity( ds_back, 50 );
    ds_back.setAttributeNode(ds_attr);
    ds_body.appendChild( ds_back );


    //-------------------------------------------
    // create a middle div:
    //-------------------------------------------
    ds_front = document.createElement("div");
	ds_attr  = document.createAttribute("class");
    ds_front.id                      = "sl_foreground";
	ds_attr.nodeValue                = "sl_foreground";
    ds_front.style.zIndex            = ds_back.style.zIndex + 100;
    ds_front.style.position          = "absolute";
    ds_front.style.top               = "50%";
    ds_front.style.left              = "50%";
    ds_front.setAttributeNode(ds_attr);
    ds_body.appendChild( ds_front );
    in_width  = parseInt( m_get_style( ds_front ).width  );
    in_height = parseInt( m_get_style( ds_front ).height );
    ds_front.style.marginLeft        = "-" + in_width/2  + "px";
    ds_front.style.marginTop         = "-" + in_height/2 + "px";

    //-------------------------------------------
    // show close button if selected:
    //-------------------------------------------
    if ( bo_show_close ) {
        ds_button = document.createElement("div");
	    ds_attr   = document.createAttribute("class");
        ds_button.id                 = "sl_close";
        ds_attr.nodeValue            = "sl_close";
        ds_button.style.zIndex       = ds_front.style.zIndex + 100;
        ds_button.style.position     = "absolute";
        ds_button.style.top          = "50%";
        ds_button.style.left         = "50%";
        if (window.attachEvent) { // msie, opera;
            ds_button.attachEvent( "onclick", m_progress_stop );
        } else if (window.addEventListener) { // mozilla;
            ds_button.addEventListener( "click", m_progress_stop, true );
        }
        ds_button.setAttributeNode(ds_attr);
        ds_body.appendChild( ds_button );
    }


    //-------------------------------------------
    // create middle title:
    //-------------------------------------------
    if ( str_title ) {
        ds_title = document.createElement("div");
	    ds_attr  = document.createAttribute("class");
        ds_attr.nodeValue                = "sl_title";
   	    ds_title.id                      = "sl_title";
        ds_title.innerHTML               = str_title;
        ds_title.setAttributeNode(ds_attr);
        ds_front.appendChild( ds_title );
    }


    //-------------------------------------------
    // insert object:
    //-------------------------------------------
    if ( ds_object ) { 
        ds_front.appendChild( ds_object );
    }

    //-------------------------------------------
    // create middle text:
    //-------------------------------------------
    if ( str_text ) {
        ds_text = document.createElement("div");
        ds_attr = document.createAttribute("class");
  	    ds_attr.nodeValue                = "sl_text";
   	    ds_text.id                       = "sl_text";
        ds_text.innerHTML                = str_text;
        ds_text.setAttributeNode(ds_attr);
        ds_front.appendChild( ds_text );
    }
} // end of m_slide_start


/**
 * function m_slide_stop()
 * close slide window
*/
function m_slide_stop()
{
    var ds_back=null;
    var ds_front=null;
    var ds_button=null;

    //-------------------------------------------
    // remove close button (if present):
    //-------------------------------------------
    ds_button = document.getElementById("sl_close");
    if ( ds_button ) {
        ds_button.parentNode.removeChild(ds_button);
    }

    //-------------------------------------------
    // remove middle div:
    //-------------------------------------------
    ds_front = document.getElementById("sl_foreground");
    if ( ds_front ) {
        ds_front.parentNode.removeChild(ds_front);
    }

    //-------------------------------------------
    // remove background:
    //-------------------------------------------
    ds_back = document.getElementById("sl_background");
    if ( ds_back ) {
        ds_back.parentNode.removeChild(ds_back);
    }
} // end of m_slide_stop


/**
 * function m_move
 * move progressbar
*/
var bo_mv_left = false;
var in_mv_step = 1;
function m_move()
{
    var ds_progress = document.getElementById("sl_progress");
    var ds_bar      = document.getElementById("sl_pbar");
    var in_pos      = 0;    // actual position
    var in_l_border = 0;    // left  border (change direction)
    var in_r_border = 0;    // right border (change direction)

    //-------------------------------------------
    // check objects:
    //-------------------------------------------
    if ( !ds_bar || !ds_progress ) {
        return;
    }

    //-------------------------------------------
    // check if a left margin is set:
    //-------------------------------------------
    if ( !ds_bar.style.marginLeft ) {
        ds_bar.style.marginLeft = "0px";
    }

    
    //-------------------------------------------
    // get actual position and borders:
    //-------------------------------------------
    in_pos      = parseInt( m_get_style(ds_bar).marginLeft );
    in_l_border = 0;
    in_r_border =   parseInt( m_get_style(ds_progress).width )
                  - parseInt( m_get_style(ds_bar).width ) ;

    
    //-------------------------------------------
    // do the move:
    //-------------------------------------------
    if ( bo_mv_left == false ) {
        in_pos += in_mv_step;
        if ( in_pos > in_r_border ) {
            bo_mv_left = true;
            in_pos = in_r_border;
        }
    } else {  
        in_pos -= in_mv_step;
        if ( in_pos < in_l_border ) {
            bo_mv_left = false;
            in_pos = in_l_border;
        }
    }
    ds_bar.style.marginLeft = in_pos + "px";
} // end of m_move


/**
 * function m_opacity
 * change opacity of a given element ds_object
 *
 * @param[in]   object  ds_object
 * @param[in]   int     in_opacity          in percent
*/
function m_opacity( ds_object, in_opacity )
{
	ds_object.style.opacity      = (in_opacity/100);
	ds_object.style.MozOpacity   = (in_opacity/100);
	ds_object.style.KhtmlOpacity = (in_opacity/100);
	ds_object.style.filter       = "alpha(opacity="+in_opacity+")";
} // end of m_opactiy


/**
 * function m_get_style
 * get current style of an object
 *
 * @param[in]   object  ds_object
*/
function m_get_style( ds_object )
{
    if ( ds_object ) {
        if ( ds_object.currentStyle ) {
            return ds_object.currentStyle;
        } else if ( document.defaultView ) {
            if ( document.defaultView.getComputedStyle ) {
                return document.defaultView.getComputedStyle( ds_object, "" );
            }
        }
        return ds_object.style;
    }
} // end of m_get_style


/**
 * function m_preload_img
 * preload an image
 *
 * @param[in]   str_url
*/
function m_preload_img( str_url ) {
    var ds_img = new Image();
    ds_img.src = str_url;
}
m_preload_img( "/public/img/bar2.gif" );
