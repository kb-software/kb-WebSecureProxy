"use strict";
var HOB = function(){
    var dsc_args = null;
    var strc_address_wsp = null;
    
function m_initialize(dsp_args) {
    var strl_address_wsp = document.location.protocol + "//" + document.location.host;
    if ( document.location.port && (document.location.host.indexOf(":") == -1) ) {
        strl_address_wsp += ":" + document.location.port;
    }
    dsc_args = dsp_args;
    strc_address_wsp = strl_address_wsp;
}
//strp_url is expected to be an absolute url (starting with protocoll)
function m_change_url_to_wsg(strp_url) {
    //use url with session id, if cookies disabled
    return strc_address_wsp + strg_url_session_id + "/wsg/" + strp_url;
}
//strp_url is expected to be a host-absolute path (starting with a /)
function m_get_hobweblaunch_link(strp_url) {
    return strc_address_wsp + strg_url_session_id +'/hoblaunch'+ strp_url;
}

function m_convert_jnlp_links() {
    var dsl_links = document.getElementsByTagName('a');
    for(var inl1=0; inl1<dsl_links.length; inl1++) {
        //use attribute to get the non interpreted path
        var strl_href = dsl_links[inl1].getAttribute("href");
        if(    strl_href != null
            && (strl_href.endsWith('.jnlp') || strl_href.indexOf('.jnlp?') != -1) 
            &&  strl_href.indexOf('hoblaunch') == -1) { //hobweblaunch:
            if(!strl_href.startsWith('/'))
                strl_href = '/protected/'+strl_href;
            dsl_links[inl1].setAttribute('href', m_get_hobweblaunch_link(strl_href));
        }
    }
}


function m_open_wsg_input() {
    var str_dest = document.connectform.url.value;
    if (    str_dest.length < 1
         || str_dest.toLowerCase() == "http://" ) {
        document.connectform.url.focus();
        return false;
    }
    if ( str_dest.charAt(0)!='/' ) {
        if ( str_dest.match(/^(http|https|):/i) ) {
        } else {
            str_dest = "http://" + str_dest;
        }
    }
    var strl_wsg_url = HOB.m_change_url_to_wsg(str_dest);
    window.open( strl_wsg_url, "_blank" );
    return false;
}

function m_load() {
    //add bookmark listeners
    var dsl_bm_left = document.querySelector("#bookmarks .carousel-left");
    var dsl_bm_right = document.querySelector("#bookmarks .carousel-right");
    var dsl_bm_carousel = document.getElementById("bookmarks-inner");
    var dsl_bm = document.getElementById("bookmarks");
    var inl_scroll_step = dsl_bm_carousel.offsetWidth/4;
    
    var bol_still_scrolling = false;
    function ml_scroll_left(e) {
        if(e.button != 0)
            return;
        bol_still_scrolling = true;
        var inl_sl = dsl_bm_carousel.scrollLeft;
        var inl_bias = dsl_bm_carousel.offsetLeft;
        for (var inl1 = dsl_bm_carousel.children.length-1; inl1 > 0; inl1--) {
            if(dsl_bm_carousel.children[inl1].offsetLeft-inl_bias < inl_sl - 30) { 
                //if left edge is at least 30 px outside of viewport
                inl_sl = dsl_bm_carousel.children[inl1].offsetLeft-inl_bias;
                break;
            }
        }
        
        m_remove_class(dsl_bm, 'scroll-end');

        if(inl1 == 0) {
            inl_sl = 0;
            m_add_class(dsl_bm, 'scroll-start');
        } else {
            setTimeout(function(){
                if(bol_still_scrolling) {
                    ml_scroll_left(e);
                }
            }, 500);
        }
        m_scroll_toW(dsl_bm_carousel, inl_sl, 300);
    }
    function ml_scroll_right(e) {
        if(e.button != 0)
            return;
        bol_still_scrolling = true;
        var inl_sl = dsl_bm_carousel.scrollLeft+dsl_bm_carousel.offsetWidth;//right edge of viewport
        var inl_bias = dsl_bm_carousel.offsetLeft;
        for (var inl1 = 0; inl1 < dsl_bm_carousel.children.length; inl1++) {
            if(dsl_bm_carousel.children[inl1].offsetLeft -inl_bias + dsl_bm_carousel.children[inl1].offsetWidth > inl_sl + 30) {
                //if right edge is at least 30 px outside of viewport
                inl_sl = dsl_bm_carousel.children[inl1].offsetLeft-inl_bias + dsl_bm_carousel.children[inl1].offsetWidth - dsl_bm_carousel.offsetWidth;
                break;
            }
        }
        
        m_remove_class(dsl_bm, 'scroll-start');

        if(inl_sl >= (dsl_bm_carousel.scrollWidth-dsl_bm_carousel.offsetWidth) ) {
            inl_sl = dsl_bm_carousel.scrollWidth-dsl_bm_carousel.offsetWidth;
            m_add_class(dsl_bm, "scroll-end");
        } else {
            setTimeout(function(){
                if(bol_still_scrolling) {
                    ml_scroll_right(e);
                }
            }, 500);
        }
        m_scroll_toW(dsl_bm_carousel, inl_sl, 300);
    }
    dsl_bm_right.onmousedown = ml_scroll_right;
    dsl_bm_left.onmousedown = ml_scroll_left;
    document.addEventListener("mouseup", function(e) {
        if(e.button == 0) {
            bol_still_scrolling = false;
        }
    });
    
    if(dsl_bm_carousel.children.length == 0) {
        dsl_bm_left.style.display = "none";
        dsl_bm_right.style.display = "none";
    } else {
        //collect available targets:
        var astrl_links = {};
        var strl_host = strc_address_wsp + strg_url_session_id;
        for(var inl1=0; inl1 < dsg_bm.astrs_portlets_filter_config.length; inl1++){
            var temp = [];
            var dsl_links = document.querySelectorAll('#'+dsg_bm.astrs_portlets_filter_config[inl1]+'-content > * a[href]')
            for(var inl2=0; inl2 < dsl_links.length; inl2++){
                var strl_href = dsl_links[inl2].href;
                if (strl_href.startsWith(strl_host))
                    strl_href = strl_href.substr(strl_host.length);
                temp.push(strl_href);
            }
            astrl_links[dsg_bm.astrs_portlets_filter_config[inl1]] = temp;
        }
        console.log(astrl_links);
        //create copy of live-view as we may remove items in loop
        var children = Array.prototype.slice.call(dsl_bm_carousel.children);
        for(var inl1=0; inl1 < children.length; inl1++){
            var strl_state = dsg_bm.m_check_target_available(children[inl1], dsc_args.astrc_portlets, astrl_links);
            if(strl_state != null) {
                console.log('Hiding bookmark "'+children[inl1].textContent.trim()
                    +'" <'+children[inl1].getAttribute('href')+'> Reason: '+strl_state);
                dsl_bm_carousel.removeChild(children[inl1])
            } else {
                dsg_bm.m_update_link(children[inl1]);
            }
        }
    }
    
    if(dsl_bm_carousel.offsetWidth >= dsl_bm_carousel.scrollWidth) {
        m_add_class(dsl_bm, "scroll-end");
    }
    
    var dsl_infos = document.querySelectorAll("#portlets .info");
    for (var inl1 = 0; inl1 < dsl_infos.length; inl1++) {
        dsl_infos[inl1].onclick = function(e) {
            e.preventDefault();
            e.stopPropagation();
            var dsl_title = e.target;
            while(!m_has_class(dsl_title, 'fold-title'))
                dsl_title = dsl_title.parentElement;
            var bol_has_title = m_has_class(dsl_title, 'desc-open'); 
            var dsl_open = document.querySelectorAll('#portlets .desc-open');
            for(var inl2 = 0; inl2 < dsl_open.length; inl2++) {
                m_remove_class(dsl_open[inl2], 'desc-open');
            }
            if(!bol_has_title) {
                m_add_class(dsl_title, 'desc-open');
            }
        }
    }
    
    window.addEventListener('hashchange', function(){
        if(location.hash && location.hash.length > 1) {
            m_open_fold(location.hash.substring(1));
        } else {
            m_close_fold();
        }
    });
    
    if(dsg_java.m_use_hoblaunch()) {
        m_convert_jnlp_links();
    }
    
    var bol_focused = false;
    if ( document.getElementById("change-password-now") ) {
         document.getElementById("change-password-now").focus();
         bol_focused = true;
    }
    
    if(location.hash && location.hash.length > 1) {
        var strl_portlet = location.hash.substring(1);
        var dsl_a_title = document.getElementById(strl_portlet+'-title');
        if(dsl_a_title) {
            m_open_fold(strl_portlet);
            if(location.hash == '#wsg' && document.connectform && !bol_focused) {
                //focus same element as in old gui
                document.connectform.url.focus();
            } else if (dsl_a_title.onclick) {
                dsl_a_title.onclick(); //try to open popup
            }
        }
    }
}

function m_scroll_toW(dsp_element, inp_to, inp_duration) {
    if (inp_duration <= 0) return;
    var inl_difference = inp_to - dsp_element.scrollLeft;
    var inl_perTick = inl_difference / inp_duration * 20;

    setTimeout(function() {
        dsp_element.scrollLeft = dsp_element.scrollLeft + inl_perTick;
        if (dsp_element.scrollLeft === inp_to) return;
        m_scroll_toW(dsp_element, inp_to, inp_duration - 20);
    }, 20);
}

function m_update_fold_link(strp_portlet, ds_href) {
    //updated link opens the linked page (by onclick) and the portlet view (by hashchange from link following)
    //as link is only saved in closure, dynamic conversion of jnlp type muste be done beforehand
    var dsp_a = document.getElementById(strp_portlet+'-title')
    
    var dsl_reopen = document.querySelector('#'+strp_portlet+'-content a.reopen');
    if(dsl_reopen) {
        dsl_reopen.href = ds_href;
    }
    if(ds_href.endsWith(".jnlp")) {
        m_add_class(dsp_a, "download");
    }
    dsp_a.onclick = function(e) {
        if(document.querySelector('#portlets.all-closed') != null) {
            e.preventDefault();
        }
        window.location.href = ds_href;
    }

}

function m_open_fold(strp_portlet) {
    var dsl_title_container = document.getElementById('portlets');
    var dsl_content_container = document.getElementById('content-wrapper');
    var dsl_open_title = document.getElementById(strp_portlet+"-title");
    var dsl_open_content = document.getElementById(strp_portlet+"-content");
    var bol_opened = !dsl_open_title || dsl_open_title.className.indexOf('closed') == -1;
    //if title could not be found (invalid hash value), close all portlets
    var dsl_oth = document.querySelectorAll('.fold-title:not(.closed), .fold-content:not(.closed)');
    //close all others
    for(var inl1=0; inl1<dsl_oth.length; inl1++) {
        m_add_class(dsl_oth[inl1], 'closed');
    }
    
    if(!bol_opened) { //only open if it wasn't perviosly opened
        m_remove_class(dsl_open_title, 'closed');
        m_remove_class(dsl_open_content, 'closed');
        m_remove_class(dsl_title_container, 'all-closed');
        m_remove_class(dsl_content_container, 'all-closed');
        dsl_open_title.blur(); //remove focus
    } else {
        m_add_class(dsl_title_container, 'all-closed');
        m_add_class(dsl_content_container, 'all-closed');
    }
}

function m_close_fold() {
    var dsl_title_container = document.getElementById('portlets');
    var dsl_content_container = document.getElementById('content-wrapper');
    var dsl_oth = document.querySelectorAll('.fold-title:not(.closed), .fold-content:not(.closed)');
    //close all others
    for(var inl1=0; inl1<dsl_oth.length; inl1++) {
        m_add_class(dsl_oth[inl1], 'closed');
    }
    
    m_add_class(dsl_title_container, 'all-closed');
    m_add_class(dsl_content_container, 'all-closed');
}

function m_update_mobile_selection() {
    var dsl_list = document.querySelector('#mobile-content ul');
    var strl_os = m_detect_os();
    if(strl_os == "android" || strl_os == "ios") {
        m_add_class(dsl_list, strl_os);
    } else { //TODO hide or display all?
        m_add_class(dsl_list, "desktop");
    }
}

return {
    'm_initialize': m_initialize,
    'm_change_url_to_wsg': m_change_url_to_wsg,
    'm_load': m_load,
    'm_update_fold_link': m_update_fold_link,
    'm_update_mobile_selection': m_update_mobile_selection,
    'm_open_wsg_input': m_open_wsg_input,
    'm_convert_jnlp_links': m_convert_jnlp_links,
    'm_get_hobweblaunch_link': m_get_hobweblaunch_link,
}
} ();
