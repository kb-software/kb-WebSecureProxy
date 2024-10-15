/*
HOBLaunch Protocoll Availability check based on: 
https://github.com/ismailhabib/custom-protocol-detection

The MIT License (MIT)

Copyright (c) 2015 Ismail Habib Muhammad

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

var dsg_protocol_check = (function(){
function _registerEvent(target, eventType, cb) {
    if (target.addEventListener) {
        target.addEventListener(eventType, cb);
        return {
            remove: function () {
                target.removeEventListener(eventType, cb);
            }
        };
    } else {
        target.attachEvent(eventType, cb);
        return {
            remove: function () {
                target.detachEvent(eventType, cb);
            }
        };
    }
}

function _createHiddenIframe(target, uri) {
    var iframe = document.createElement("iframe");
    iframe.src = uri;
    iframe.id = "hiddenIframe";
    iframe.style.display = "none";
    target.appendChild(iframe);

    return iframe;
}

function openUriWithHiddenFrame(uri, failCb, successCb) {

    var timeout = setTimeout(function () {
        failCb();
        handler.remove();
    }, 1000);

    var iframe = document.querySelector("#hiddenIframe");
    if (!iframe) {
        iframe = _createHiddenIframe(document.body, "about:blank");
    }

    var handler = _registerEvent(window, "blur", onBlur);

    function onBlur() {
        clearTimeout(timeout);
        handler.remove();
        successCb();
    }

    iframe.contentWindow.location.href = uri;
}

function openUriWithTimeoutHack(uri, failCb, successCb) {
    
    var timeout = setTimeout(function () {
        failCb();
        handler.remove();
    }, 1000);

    //handle page running in an iframe (blur must be registered with top level window)
    var target = window;
    while (target != target.parent) {
        target = target.parent;
    }

    var handler = _registerEvent(target, "blur", onBlur);

    function onBlur() {
        clearTimeout(timeout);
        handler.remove();
        successCb();
    }

    window.location = uri;
}

function openUriUsingFirefox(uri, failCb, successCb) {
    var iframe = document.querySelector("#hiddenIframe");

    if (!iframe) {
        iframe = _createHiddenIframe(document.body, "about:blank");
    }

    try {
        iframe.contentWindow.location.href = uri;
        successCb();
    } catch (e) {
        if (e.name == "NS_ERROR_UNKNOWN_PROTOCOL") {
            failCb();
        }
    }
}

function openUriUsingIEInOlderWindows(uri, failCb, successCb) {
    if (getInternetExplorerVersion() === 10) {
        openUriUsingIE10InWindows7(uri, failCb, successCb);
    } else if (getInternetExplorerVersion() === 9 || getInternetExplorerVersion() === 11) {
        openUriWithHiddenFrame(uri, failCb, successCb);
    } else {
        openUriInNewWindowHack(uri, failCb, successCb);
    }
}

function openUriUsingIE10InWindows7(uri, failCb, successCb) {
    var timeout = setTimeout(failCb, 1000);
    window.addEventListener("blur", function () {
        clearTimeout(timeout);
        successCb();
    });

    var iframe = document.querySelector("#hiddenIframe");
    if (!iframe) {
        iframe = _createHiddenIframe(document.body, "about:blank");
    }
    try {
        iframe.contentWindow.location.href = uri;
    } catch (e) {
        failCb();
        clearTimeout(timeout);
    }
}

function openUriInNewWindowHack(uri, failCb, successCb) {
    var myWindow = window.open('', '', 'width=0,height=0');

    myWindow.document.write("<iframe src='" + uri + "'></iframe>");

    setTimeout(function () {
        try {
            myWindow.location.href;
            myWindow.setTimeout("window.close()", 1000);
            successCb();
        } catch (e) {
            myWindow.close();
            failCb();
        }
    }, 1000);
}

function openUriWithMsLaunchUri(uri, failCb, successCb) {
    var cancelTimeout = setTimeout(successCb, 1000); 
    //if user cancels opening, neither cb is invoked
    navigator.msLaunchUri(uri,
        function() { clearTimeout(cancelTimeout); successCb()},
        function() { clearTimeout(cancelTimeout); failCb()}
    );
}

function checkBrowser() {
    var isOpera = !!window.opera || navigator.userAgent.indexOf(' OPR/') >= 0;
    var ua = navigator.userAgent.toLowerCase();
    return {
        isOpera   : isOpera,
        isFirefox : typeof InstallTrigger !== 'undefined',
        isSafari  : (~ua.indexOf('safari') && !~ua.indexOf('chrome')) || Object.prototype.toString.call(window.HTMLElement).indexOf('Constructor') > 0,
        isIOS     : /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream,
        isChrome  : !!window.chrome && !isOpera,
        isIE      : /*@cc_on!@*/false || !!document.documentMode // At least IE6
    }
}

function getInternetExplorerVersion() {
    var rv = -1;
    if (navigator.appName === "Microsoft Internet Explorer") {
        var ua = navigator.userAgent;
        var re = new RegExp("MSIE ([0-9]{1,}[\.0-9]{0,})");
        if (re.exec(ua) != null)
            rv = parseFloat(RegExp.$1);
    }
    else if (navigator.appName === "Netscape") {
        var ua = navigator.userAgent;
        var re = new RegExp("Trident/.*rv:([0-9]{1,}[\.0-9]{0,})");
        if (re.exec(ua) != null) {
            rv = parseFloat(RegExp.$1);
        }
    }
    return rv;
}

function m_test(uri, cb) {
    function failCallback() {
        cb("error");
    }

    function successCallback() {
        cb("success");
    }

    if (navigator.msLaunchUri) { //for IE and Edge in Win 8 and Win 10
        openUriWithMsLaunchUri(uri, failCallback, successCallback);
    } else {
        var browser = checkBrowser();

        if (browser.isFirefox) {
            openUriUsingFirefox(uri, failCallback, successCallback);
        } else if (browser.isChrome || browser.isOpera  || browser.isIOS) {
            openUriWithTimeoutHack(uri, failCallback, successCallback);
        } else if (browser.isIE) {
            openUriUsingIEInOlderWindows(uri, failCallback, successCallback);
        } else if (browser.isSafari) {
            openUriWithHiddenFrame(uri, failCallback, successCallback);
        } else {
            //not supported, implement please
            cb("unknown");
        }
    }
}

    return {
        'm_test_uri': m_test,
    }
})();
// ---- end of protocol check


/**
* some functions for test if java plugin is installed and works.
*/
var dsg_java = function() {
function m_is_java_supported() {
    var dsl_mime_types = navigator.mimeTypes;
    for( var i=0,size=dsl_mime_types.length; i<size; i++ ) {
        var dsl_type = dsl_mime_types[i].type;
        if(dsl_type.startsWith( "application/x-java-applet" ))
            return true;
    }

    var strl_user_agent = navigator.userAgent;
    var bol_is_edge = strl_user_agent.indexOf( 'Edge/' ) >= 0;

    if( bol_is_edge )
        return false;

    var bol_is_ie = strl_user_agent.indexOf( 'MSIE ' ) >= 0;

    if( bol_is_ie )
        return true;

    var bol_is_ie11 = strl_user_agent.indexOf( 'Trident/' ) >= 0;
    if( bol_is_ie11 )
        return true;

    return false;
}

function m_is_java_enabled() {
    if( !m_is_java_supported() )
        return false;
    if( navigator.javaEnabled ) {
        return navigator.javaEnabled();
    }
    return false;
}

function m_check_hoblaunch_available(mp_cb) {
    //TODO: this is a fictional URI, use something existing?
    //Pro no error message from HobLaunch, Con: less Informative to user
    dsg_protocol_check.m_test_uri('hobweblaunch:/testInstalled/', mp_cb);
}

function m_is_webstart_enforced() {
    return m_get_cookie('webstart-enforced') == '1';
}

function m_use_hoblaunch() {
    return m_get_cookie('hoblaunch') == '1';
}


function m_set_webstart_enforced(bop_val) {
    m_set_cookie('webstart-enforced', bop_val ? '1' : '0');
}
function m_set_hoblaunch(bop_val) {
    m_set_cookie('hoblaunch', bop_val ? '1' : '0');
}

    return {
        'm_use_applets': function m_use_applets() {
            return m_is_java_enabled() && !m_is_webstart_enforced();
        },
        'm_use_hoblaunch': m_use_hoblaunch,
        
        'm_is_java_enabled': m_is_java_enabled,
        'm_is_webstart_enforced': m_is_webstart_enforced,
        
        'm_set_webstart_enforced': m_set_webstart_enforced,
        'm_set_hoblaunch': m_set_hoblaunch,
        
        'm_check_hoblaunch_available': m_check_hoblaunch_available,
    }
}();


