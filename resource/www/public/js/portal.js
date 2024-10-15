// Add backward compatibilty for IE
if ( !String.prototype.startsWith ) {
    String.prototype.startsWith = function( searchString, position ){
        position = position || 0;
        return this.substr( position, searchString.length ) === searchString;
    };
}
if ( !String.prototype.endsWith ) {
    String.prototype.endsWith = function( search, this_len ){
        if (this_len === undefined || this_len > this.length) {
			this_len = this.length;
		}
		return this.substring(this_len - search.length, this_len) === search;    
    };
}
if (!Math.sign) {
  Math.sign = function(x) {
    return ((x > 0) - (x < 0)) || +x;
  };
}
if(!String.prototype.trim) {
	String.prototype.trim = function () {
		return this.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g, '');
	};
}

function m_format_date( in_milliseconds ) {
    var tm_stamp = new Date( in_milliseconds );
    var Std   = tm_stamp.getHours();
    var Min   = tm_stamp.getMinutes();
    var Sec   = tm_stamp.getSeconds();
    var Dat   = tm_stamp.getDate();
    var Month = tm_stamp.getMonth() + 1;
    var Year  = tm_stamp.getYear();
    
    return            ((Dat < 10)   ? "0"  + Dat   : Dat  ) + "."
                    + ((Month < 10) ? "0"  + Month : Month) + "."
                    + ((Year < 999) ? Year + 1900  : Year ) + " "
                    + ((Std < 10)   ? "0"  + Std   : Std  ) + ":"
                    + ((Min < 10)   ? "0"  + Min   : Min  ) + ":"
                    + ((Sec < 10)   ? "0"  + Sec   : Sec  );
}

function m_write_date( in_ms ) {
    document.write(m_format_date( in_ms ));
}

//does not work on svg elements, as className is not a string, but an Object (SVGAnimatedString)
function m_has_class(dsp_element, strp_class) {
    return (dsp_element.className.indexOf(strp_class) != -1);
}

function m_add_class(dsp_element, strp_class) {
    if(dsp_element.className.indexOf(strp_class) == -1)
        dsp_element.className += " "+strp_class;
}

function m_remove_class(dsp_element, strp_class) {
    dsp_element.className = dsp_element.className.replace(
        new RegExp('(?:^|\\s+)'+ strp_class + '(?:\\s+|$)'), ' ');
}

var dsg_last_dd = null;
//onclick="m_toggle_menu('menu-settings'); return false;"
function m_toggle_menu(strp_menu_id) {
    var dsl_element = document.getElementById(strp_menu_id);
    
    if(! m_has_class(dsl_element, 'open') && dsg_last_dd != dsl_element) {
        if(dsg_last_dd) { //close last dd
            m_remove_class(dsg_last_dd, 'open');
        }
        m_add_class(dsl_element, 'open');
        dsg_last_dd = dsl_element;
    } else {
        m_remove_class(dsl_element, 'open');
        dsg_last_dd = null;
    }
}
document.addEventListener("click", function(e) {
    var dsl_target = e.target;
    if(dsl_target.tagName.toLowerCase() != 'svg' //m_has_class does not work on svg elements
      && m_has_class(dsl_target, 'openMenu') 
      && m_has_class(dsl_target.parentElement, 'ddmenu')) {
        var dsl_element = dsl_target.parentElement;
        if(! m_has_class(dsl_element, 'open')) {
            if(dsg_last_dd) { //close last dd
                m_remove_class(dsg_last_dd, 'open');
            }
            m_add_class(dsl_element, 'open');
            dsg_last_dd = dsl_element;
        } else {
            m_remove_class(dsl_element, 'open');
            dsg_last_dd = null;
        }
        e.preventDefault();
    } else if(dsg_last_dd != null) {
        while(dsl_target != null) {
            if(dsl_target == dsg_last_dd) 
                return; // click on or inside menu -> ignore
            dsl_target = dsl_target.parentElement;
        }
        m_remove_class(dsg_last_dd, 'open');
        dsg_last_dd = null;
    }
});

function m_set_cookie(cook_name, expand) {
  document.cookie = cook_name + "=" + expand + "; path=/ ; expires=Fri, 31 Dec 9999 23:59:59 GMT";
}

function m_get_cookie(cook_name) {
  var expand = null;
  var cookie = null;
  try {
      cookie = document.cookie;
  } catch(e) {
      return null;
  }
  if (cookie) {
    var expand_start = cookie.indexOf(cook_name + "=");
    var expand_end = cookie.indexOf("; ", expand_start);
    if (expand_start != -1) {
      expand_start= expand_start+ cook_name.length +1;
      if(expand_end == -1)
        expand = cookie.substring(expand_start);
      else
        expand = cookie.substring(expand_start, expand_end);
    }
  }
  return expand;
}

function m_cookies_enabled() {
    try {
      document.cookie = 'cookietest=1';
      var cookiesEnabled = document.cookie.indexOf('cookietest=') !== -1;
      document.cookie = 'cookietest=1; expires=Thu, 01-Jan-1970 00:00:01 GMT';
      return cookiesEnabled;
    } catch (e) {
      return false;
    }
}

function m_check_embedded_use() {
    if(top != self) {
        //invalid iframe use detected
        try {
            top.location.href = location.href
        } catch(e) {
            //we are running in an sanboxed iframe
            //body is not yet created, so this is shortest option
            document.write('<div style="position: absolute; width: 100%; height: 100%; background: black; color: red; z-index: 1000">Error: Forbidden use of RD VPN in a sandboxed frame!</div>');
        }
    }
}

function m_insert_wordbreak_spaces(strp_text, dsp_replace_regex) {
    //add a zero-width space after each delimiter to allow line breaking inside words
    return strp_text.replace(dsp_replace_regex, '$&\u200B');
} 