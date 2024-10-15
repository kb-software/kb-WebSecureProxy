var str_req_method  = "POST";              // out request method
var str_req_url     = "quarantine.hsl";    // requested url
var in_req_interval = 3000;                // request interval in milliseconds
var in_req_tmmax    = 60000;               // max time to request in milliseconds
var bo_do_request   = true;
var ds_xmlhttp      = null;
if ( !nav_area2_href ) {
    var nav_area2_href = "/public/login.hsl";
}


//---------------------------------------
// receive object
//---------------------------------------
var ds_receive = {
    // variables:
    ds_tasks    : new Array(),
    str_forward : null,
    bo_error    : false,

    // functions:
    m_add_task : function ( ds_task_in ) 
    {
        ds_receive.ds_tasks.push( ds_task_in );
    },

    m_add_forward : function ( str_url )
    {
        ds_receive.str_forward = str_url;
    },

    m_set_error : function ( str_value )
    {
        if ( str_value.toLowerCase() == "yes" ) {
            ds_receive.bo_error = true;
        }
    },

    m_reset : function()
    {
        ds_receive.ds_tasks    = new Array();
        ds_receive.str_forward = null;
        ds_receive.bo_error    = false;
    }
};



function m_message( str_message ) 
{
    if(document.getElementById("message")){
        document.getElementById("message").innerHTML += str_message;
    }
}
            

function m_init() 
{ 
    if (typeof XMLHttpRequest != 'undefined') {
        ds_xmlhttp = new XMLHttpRequest();
    }
    if (!ds_xmlhttp) {
        try {
            ds_xmlhttp  = new ActiveXObject("Msxml2.XMLHTTP");
        } catch(e) {
            try {
                ds_xmlhttp  = new ActiveXObject("Microsoft.XMLHTTP");
            } catch(e) {
                ds_xmlhttp  = null;
            }
        }
    }
}

            
function m_request() 
{
    if (ds_xmlhttp) {
        ds_xmlhttp.open(str_req_method, str_req_url, true);
        ds_xmlhttp.onreadystatechange = m_cb_request;
        ds_xmlhttp.send("quarantine=GetStatus");
    } else {
        alert("no xmlhttp object");
    }
}   


function m_cb_request()
{
    if ( ds_xmlhttp.readyState == 4 ) {
        //-------------------------------
        // reset last receive:
        //-------------------------------
        ds_receive.m_reset();

        //-------------------------------
        // handle received data:
        //-------------------------------
        m_handle_xml( ds_xmlhttp.responseText );

        //-------------------------------
        // check for error:
        //-------------------------------
        if ( ds_receive.bo_error == true ) {
            HOB_send("Logout");
        }

        //-------------------------------
        // forward browser (if set)
        //-------------------------------
        if ( ds_receive.str_forward ) {
            m_move_to(ds_receive.str_forward);
            return;
        }
        

        //-------------------------------
        // update side information:        
        //-------------------------------
        m_update_view();

        //-------------------------------
        // should we do another request?
        //-------------------------------
        if ( bo_do_request == true ) {
            window.setTimeout("m_request()", in_req_interval);
        }
    }
}
            

function m_handle_xml( str_xml )
{
    // initialize some variables:
    var xml_doc;        // our xml document
    var ds_pnode;       // parent dome noce
    var ds_cnode;       // children dome node

    if ( !str_xml ) {
        return;
    }
                
    try {
        //----------------------------------------------
        // get xml parser:
        //----------------------------------------------
        if (document.implementation.createDocument) {
            var parser = new DOMParser();
            xml_doc = parser.parseFromString(str_xml, "text/xml");
        } else if (window.ActiveXObject) {
            xml_doc = new ActiveXObject("Microsoft.XMLDOM")
            xml_doc.async="false";
            xml_doc.loadXML(str_xml);
        }
    
        //----------------------------------------------
        // get root node:
        //----------------------------------------------
        ds_pnode = xml_doc.documentElement;
        if ( ds_pnode.nodeName != "quarantine" ) {
            return;
        }
                    
        //----------------------------------------------
        // parse our document:
        //----------------------------------------------
        ds_pnode = ds_pnode.firstChild;
        while ( ds_pnode ) {
            if ( ds_pnode.nodeType == 1 ) {
                //--------------------------------------
                // get childnode:
                //--------------------------------------
                ds_cnode = ds_pnode.firstChild;
                if ( !ds_cnode ) {
                    // no childnode -> get next node
                    ds_pnode = ds_pnode.nextSibling;
                    continue; 
                }


                //--------------------------------------
                // handle node:
                //--------------------------------------
                switch ( ds_pnode.nodeName.toLowerCase() ) {
                    case "error":
                        if ( ds_cnode.nodeType == 3 ) {
                            ds_receive.m_set_error( ds_cnode.nodeValue );
                        }
                        break;

                    case "forward":
                        if ( ds_cnode.nodeType == 3 ) {
                            ds_receive.m_add_forward( ds_cnode.nodeValue );
                        }
                        break;

                    case "task":
                        m_read_task( ds_cnode );
                        break;
                }

                
            }
            ds_pnode = ds_pnode.nextSibling;
        }
    } catch (e) {
    }
}


function m_read_task( ds_pnode )
{
    // initialize some variables:
    var ads_cnode;
    var ds_task = {
        str_name   : null,
        str_status : null
    };

    
    while ( ds_pnode ) {
        if ( ds_pnode.nodeType == 1 ) {
            //------------------------------------------
            // get childnode:
            //------------------------------------------
            ds_cnode = ds_pnode.firstChild;
            if ( !ds_cnode ) {
                // no childnode -> get next node
                ds_pnode = ds_pnode.nextSibling;
                continue; 
            }
            
            //------------------------------------------
            // check type of childnode
            //------------------------------------------
            if ( ds_cnode.nodeType != 3 ) {
                // childnode is not a textnode
                ds_pnode = ds_pnode.nextSibling;
                continue;
            }

            //------------------------------------------
            // handle node:
            //------------------------------------------
            switch ( ds_pnode.nodeName.toLowerCase() ) {
                case "name":
                    ds_task.str_name   = ds_cnode.nodeValue;
                    break;
                case "status":
                    ds_task.str_status = ds_cnode.nodeValue;
                    break;
            }
        }
        ds_pnode = ds_pnode.nextSibling;
    }

    ds_receive.m_add_task( ds_task );
} // end of m_read_task


function m_update_view()
{
    // initialize some variables:
    var ds_elem   = document.getElementById('message');
    var in_len    = ds_receive.ds_tasks.length;
    var ds_task   = null;
    var ds_span   = null;
    var ds_attr   = null;
    var ds_child  = null;
    
    if ( !ds_elem ) {
        return;
    }


    //-----------------------------------
    // delete old view:
    //-----------------------------------
    ds_child = ds_elem.firstChild;
    while ( ds_child ) {
        ds_elem.removeChild( ds_child );
        ds_child = ds_elem.firstChild;
    }

    //-----------------------------------
    // add new view:
    //-----------------------------------
    for ( var i = 0; i < in_len; i++ ) {
        ds_task = ds_receive.ds_tasks[i];

        // add a newline
        if ( i > 0 ) {
            ds_span = document.createElement("br");
            ds_elem.appendChild( ds_span );
        }

        // append name:
        ds_span = document.createElement("span");
        ds_attr = document.createAttribute("class");
        ds_attr.nodeValue = "name";
        ds_span.setAttributeNode(ds_attr);
        ds_span.innerHTML = ds_task.str_name;
        ds_elem.appendChild( ds_span );

        // append status:
        ds_span = document.createElement("span");
        ds_attr = document.createAttribute("class");
        ds_attr.nodeValue = "status";
        ds_span.setAttributeNode(ds_attr);
        ds_span.innerHTML = ds_task.str_status;
        ds_elem.appendChild( ds_span );
    }
} // end of m_update_view


function m_end_requests() 
{
    bo_do_request = false;
}


function m_move_to( str_url )
{
    window.location.href = str_url;
}
            

function m_hide_java() 
{
    document.getElementById('java').style.display = 'none';
}

var in_ready    = 0;
var ds_pro_time = null; 
 
/**
 * function m_show_poll
 * show a progress bar for polling
*/
function m_show_poll( str_title )
{
    //-------------------------------------
    // init progress bar:
    //-------------------------------------
    m_progress_start( str_title );
    m_set_progress( in_ready );

    //-------------------------------------
    // show progress:
    //-------------------------------------
    m_update_poll();
    ds_pro_time = window.setTimeout("m_update_poll()", in_req_tmmax/100 );
} // end of m_show_poll


/**
 * function m_update_poll
 * update poll progress bar
*/
function m_update_poll()
{
    m_set_progress( in_ready );
    if ( in_ready == 100 ) {
        window.clearTimeout( ds_pro_time );
        m_progress_stop();
        in_ready = 0;
        HOB_send('Logout');
    } else {
        ds_pro_time = window.setTimeout("m_update_poll()", in_req_tmmax/100 );
        in_ready++;
    }
} // end of m_update_poll

//moved from portal.js, only used here
function HOB_send( str_action ) {
    var ds_post;
    var ds_form;
    var ds_action;
    
    // insert form element for sending POST /public/login.hsl
    ds_post = document.createElement("div");
    ds_post.style.display = "none";        
    
    ds_form = document.createElement("form");
    ds_form.method = "POST";
    ds_form.action = "/public/login.hsl";
    ds_form.id     = "logout_form";
    ds_post.appendChild(ds_form);
    document.body.appendChild(ds_post);
    
    ds_action   = document.createElement("INPUT");
    ds_action.type  = "hidden";
    ds_action.value = str_action;
    ds_action.name  = "logoff";
    
    document.getElementById("logout_form").appendChild(ds_action);
    document.getElementById("logout_form").submit();
}
