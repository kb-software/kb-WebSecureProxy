function m_getCurrentPage() {
    dsg_query.dsc_search = new Array();
    dsg_query.m_init();
    var ret = {};
    ret.url = "status.hsl";
    ret.file = "status.hsl";
    ret.str_handle = "-1";
    if(dsg_query.m_get("page")) {
        ret.url = decodeURIComponent(dsg_query.m_get("page"));
        if(ret.url.indexOf("?")>=0) {
            ret.file = ret.url.substring(0, ret.url.indexOf("?"));
            
            ret.query = ret.url.substring(ret.url.indexOf("?"));
            strrl_search = ret.query.slice(1).split("&");
            for ( inl_pos = 0; inl_pos < strrl_search.length; inl_pos++ ) {
                strrl_element = strrl_search[inl_pos].split("=");

                if( strrl_element[0] == strg_handleKey) {
                    ret.str_handle = decodeURIComponent( strrl_element[1].replace(/\+/i, "%20") );
                    break;
                }
            }
        }
        else {
            ret.file = ret.url;
            ret.query = "?";
        }
    } else {
        ret.replace = true;
    }
    return ret;
}

function m_updateIframeHeight() {
    var window_body = document.getElementsByTagName("body")[0];
    m_add_class(window_body, "forceScrollbarY");
    //force document to show scrollbars as this narrows the width of the iframe and may leed to more automatic linebreaks
    var iframe = document.getElementById("admin");
    iframe.style.height = 0;
    
    var minHeight = document.getElementById("menu").parentElement.offsetHeight;
            
    var iframe_cpr   = iframe.contentDocument.querySelectorAll(".copyrt")[0];
    var iframe_body = iframe.contentDocument.getElementsByTagName("body")[0];
    var iframe_head  = iframe.contentDocument.getElementsByTagName("head")[0];
    var iframe_title  = iframe.contentDocument.getElementById("title");
    var sh = 0;
    
    if( iframe_head )
        if( iframe_head.offsetHeight )
            sh = sh + iframe_head.offsetHeight;
    if( iframe_body )
        if( iframe_body.offsetHeight )
            sh = sh + iframe_body.offsetHeight;
    if( iframe_title )
        if( iframe_title.offsetHeight )
            sh = sh + iframe_title.offsetHeight;
    if( iframe_cpr )
        if( iframe_cpr.offsetHeight )
            sh = sh + iframe_cpr.offsetHeight + 8 + 8 + 5 + 10; // also add margins
    
    m_remove_class(window_body, "forceScrollbarY");
    iframe.style.height = (sh < minHeight ? minHeight : sh) + 'px';
}

function m_iframeLoaded() {
    var iframe = document.getElementById("admin");
    if(iframe.src == "" || iframe.src == "blank") return;
    
    m_updateIframeHeight();
    $(iframe.contentDocument).click(function(){m_updateIframeHeight();});
    $(iframe.contentDocument).keypress(function(){m_updateIframeHeight();});
    
    var url = iframe.contentWindow.location.pathname;
    var query = iframe.contentWindow.location.search;
    
    var state = m_getCurrentPage();
    
    if( state.file != url && !state.replace) {
        history.pushState({page: url+query}, "", "index.hsl?page="+encodeURIComponent(url+query));
    } else if (state.replace || state.query != query) { 
        //only query changed, probably a site change inside iframe -> replace iframe history entry
        history.replaceState({page: url+query}, "", "index.hsl?page="+encodeURIComponent(url+query));
    }
};

function m_restorePage() {
    /*parse search string and get current page and cluster handle*/
    var state = m_getCurrentPage();
    var iframe = document.getElementById("admin");
    
    //do NOT!!! change src while iframe attached to DOM, creates new history entry -> disables proper history navigation
    var sib = iframe.nextSibling;
    var par = iframe.parentElement;
    
    par.removeChild(iframe);
    iframe.src = state.url;
    
    par.insertBefore(iframe, sib);
    
    var linkHref = state.file.substring(state.file.lastIndexOf("/", state.file.length-2)+1);
    
    /*select navigation link*/
    $(".selected").removeClass("selected");
    //using contains selector (*=) for href because query string may be appended and absolute or relative url may be given
    if(bog_clusters) {
        $("a[href*='"+linkHref+"'][data-cluster='"+state.str_handle+"']").addClass("selected");
    } else {
        $("a[href*='"+linkHref+"']").addClass("selected");
    }
}