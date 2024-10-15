var dsg_bm = function() {

var astrs_post_portlets = [];
var astrs_configurable_portlets = ["webterm", "jwtsa", "wsg", "ppptunnel", "settings"];
var astrs_portlets_selfhosted = ["globaladmin", "webterm", "jterm", "wspuc", "hobphone", "ppptunnel", "settings"];
var astrs_portlets_filter_config = ["webterm", "jwtsa", "ppptunnel"];
var astrs_jnlps = {
    "jterm": "jlaunch.jnlp",
    "wspuc": "launchuc.jnlp",
    "hobphone": "HOBPHONE.jnlp",
    "ppptunnel": "launchppp.jnlp",
};

function m_array_contains(adsp_search, dsp_value) {
    return adsp_search.indexOf(dsp_value) != -1;
}


var adss_matchers = [
    function m_check_selfhosted(strp_url) {
        var dsl_regex = /^\/protected\/portlets\/(\w*)\/[\w\/]*\.(hsl|jnlp)(\?.*)?$/;
        if(dsl_regex.test(strp_url)) {
            var match = dsl_regex.exec(strp_url);
            if(m_array_contains(astrs_portlets_selfhosted, match[1])) {
                return match[1];
            }
        }
        return null;
    },
    function m_check_admin(strp_url) {
        if(strp_url == "/public/lib/eaadminExtern.jnlp")
            return "admin";
        return null;
    }, 
    function m_check_jwtsa(strp_url) {
        if(strp_url.startsWith("/protected/portlets/jwtsa/JWT.jnlp"))
            return "jwtsa";
        return null;
    }, 
    function m_check_wfa(strp_url) {
        if(/^\/WebFileAccess\//.test(strp_url))
            return "wfa";
        return null;
    }, 
    function m_check_password(strp_url) {
        if(strp_url == "/protected/change-password.hsl")
            return "settings";
        return null;
    }, 
    function m_check_wsg(strp_url) {
        //regex matching any valid url
        var dsl_regex = /^(https?):\/\/(([a-z0-9$_\.\+!\*\'\(\),;\?&=-]|%[0-9a-f]{2})+(:([a-z0-9$_\.\+!\*\'\(\),;\?&=-]|%[0-9a-f]{2})+)?@)?((([a-z0-9][a-z0-9-]*[a-z0-9]\.)*[a-z]{1}[a-z0-9-]*[a-z0-9]|((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2}))(:\d+)?)(((\/+([a-z0-9$_\.\+!\*\'\(\),;:@&=-]|%[0-9a-f]{2})*)*(\?([a-z0-9$_\.\+!\*\'\(\),;:@&=-]|%[0-9a-f]{2})*)?)?)?(#([a-z0-9$_\.\+!\*\'\(\),;:@&=-]|%[0-9a-f]{2})*)?$/i;
        
        if(/^\/wsg\//.test(strp_url) || dsl_regex.test( strp_url ))
            return "wsg";
        
        return null;
    }
];

function m_get_portlet (strp_url) {
    if(!strp_url) 
        return null;
    var val;
    for(var inl1=0; inl1 < adss_matchers.length && !val; inl1++) {
        val = adss_matchers[inl1](strp_url);
    }
    return val;
}

function m_update_link(dsp_link_elem) {
    //use attribute to get the non interpreted path
    var strl_url = dsp_link_elem.getAttribute("href");
    var strl_portlet = m_get_portlet(strl_url);
    
    if(!strl_portlet) {
        m_add_class(dsp_link_elem, "invalid");
        return false;
    }
    
    if (astrs_jnlps[strl_portlet] && !dsg_java.m_use_applets()) {
        var strl_url_new = "/protected/portlets/"+strl_portlet+"/"+astrs_jnlps[strl_portlet];
        if(strl_url.indexOf('?')!=-1) {
            strl_url_new += strl_url.slice(strl_url.indexOf('?'));
        }
        strl_url = strl_url_new;
    }
    if (strl_portlet == "wsg" && !(/^\/wsg\//).test(strl_url)){
        //just a normal url, redirect to wsg
        strl_url = "/wsg/"+strl_url;
    }
    if(strg_url_session_id && !strl_url.startsWith('/public')) {
        strl_url = strg_url_session_id + strl_url;
    }
    dsp_link_elem.setAttribute("href", strl_url);
    if (m_array_contains(astrs_post_portlets, strl_portlet)) {
        var dsl_params = {};
        if(strl_portlet == "wfa") {
            dsl_params.start = "";
        } else if(strl_url.indexOf('?')!=-1) {
            var astrl_params = strl_url.slice(strl_url.indexOf('?')+1).split("&");
            for(var inl1=0; inl1 < astrl_params.length; inl1++) {
                var split = astrl_params[inl1].split("=");
                dsl_params[split[0]] = decodeURIComponent(split[1]||"");
            }
        }
        
        //get closure function
        dsp_link_elem.onclick = m_do_post(dsp_link_elem, dsl_params);
    }
    
    var dsl_icon = dsp_link_elem.querySelector(".icon-bookmark");
    if(dsl_icon) {
        m_remove_class(dsl_icon, "icon-bookmark");
        m_add_class(dsl_icon, "icon-"+strl_portlet);
    }
    
    return true;
}

function m_check_target_available(dsp_link_elem, astrp_enabled_portlets, aastrp_targets) {
    //use attribute to get the non interpreted path
    var strl_url = dsp_link_elem.getAttribute("href");
    var strl_portlet = m_get_portlet(strl_url);
    
    if(!strl_portlet) {
        return 'invalid url';
    }

    if(!m_array_contains(astrp_enabled_portlets, strl_portlet)) {
        return 'portlet forbidden / not available';
    }
    
    if(aastrp_targets[strl_portlet] && !m_array_contains(aastrp_targets[strl_portlet], strl_url)) {
        return 'target not found';
    }
    return null;
}

function m_prepare_link(dsp_option_elem) {
    var strl_url = dsp_option_elem.getAttribute("value");
    var strl_portlet = m_get_portlet(strl_url);
    
    if (m_array_contains(astrs_post_portlets, strl_portlet) && strl_url.indexOf('?') != -1) {
        var strl_url_new = strl_url.slice(0, strl_url.indexOf('?')+1);
        var astrl_params = strl_url.slice(strl_url.indexOf('?')+1).split("&");
        for(var inl1=0; inl1 < astrl_params.length; inl1++) {
            var split = astrl_params[inl1].split("=");
            if(inl1 > 0)
                strl_url_new += "&";
            strl_url_new += split[0] + "=" + encodeURIComponent(split[1]||"");
        }
        dsp_option_elem.setAttribute("value", strl_url_new);
    }
}

function m_do_post(dsp_link_elem, dsp_params) {
    return function () { 
        var form = document.createElement("form");
        form.setAttribute("method", "post");
        form.setAttribute("action", dsp_link_elem.href);
        if(dsp_link_elem.target)
            form.setAttribute("target", dsp_link_elem.target);
        
        for(var strl_key in dsp_params) {
            if(dsp_params.hasOwnProperty(strl_key)) {
                var hiddenField = document.createElement("input");
                hiddenField.setAttribute("type", "hidden");
                hiddenField.setAttribute("name", strl_key);
                hiddenField.setAttribute("value", dsp_params[strl_key]);

                form.appendChild(hiddenField);
             }
        }

        document.body.appendChild(form);
        form.submit();
        
        return false;
    }
}



return {
    'm_get_portlet': m_get_portlet,
    'm_update_link': m_update_link,
    'm_prepare_link': m_prepare_link,
    'm_check_target_available': m_check_target_available,
    'astrs_configurable_portlets': astrs_configurable_portlets,
    'astrs_portlets_filter_config': astrs_portlets_filter_config,
}

}();