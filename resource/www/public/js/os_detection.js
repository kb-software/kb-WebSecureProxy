function m_detect_mobile() {
    var os = m_detect_os();
    
    return os=="windows phone" || os=="android" || os== "ios"; 
}



function m_detect_os() {
    var userAgent = navigator.userAgent || navigator.vendor || window.opera;
    
    // Windows Phone must come first because its UA also contains "Android"
    if (/windows phone/i.test(userAgent)) {
        return "windows phone";
    }

    if (/android/i.test(userAgent)) {
        return "android";
    }

    // iOS detection from: http://stackoverflow.com/a/9039885/177710
    if (/iPad|iPhone|iPod/.test(userAgent) && !window.MSStream) {
        return "ios";
    }
    
    if(/win/i.test(userAgent)) {
        return "win";
    }
    if(/linux/i.test(userAgent) || /X11/.test(userAgent)) {
        return "linux";
    }
    if(/mac/i.test(userAgent)) {
        return "mac";
    }
    return "unknown";
}
