/*
  Header file browser data interpretation and representation.
*/

#ifndef HOB_BROWSER
#define HOB_BROWSER

enum ied_browser {
  ied_browser_unknown,
  ied_browser_chrome,
  ied_browser_firefox,
  ied_browser_msie,
  ied_browser_edge,
  ied_browser_safari,
  ied_browser_opera
};

enum ied_platform {
  ied_platform_unknown,
  ied_platform_windows,
  ied_platform_mac,
  ied_platform_linux,
  ied_platform_android,
  ied_platform_freebsd,
  ied_platform_ios,
  ied_platform_sun
};

struct dsd_browser_data {
  enum ied_browser iec_browser;
  enum ied_platform iec_platform;
};

// Parse useragent string received from browser and determine the Browser Vendor
static int m_parse_user_agent(struct dsd_browser_data *adsp_out, const char *achp_useragent) {
  if (strstr(achp_useragent, "Opera") != NULL || strstr(achp_useragent, "OPR") != NULL) 
      adsp_out->iec_browser = ied_browser_opera;
    else if (strstr(achp_useragent, "Edge") != NULL) 
      adsp_out->iec_browser = ied_browser_edge;
    else if (strstr(achp_useragent, "Firefox") != NULL) 
      adsp_out->iec_browser = ied_browser_firefox;
    else if (strstr(achp_useragent, "Chrome") != NULL) 
      adsp_out->iec_browser = ied_browser_chrome;
    else if (strstr(achp_useragent, "Safari") != NULL) 
      adsp_out->iec_browser = ied_browser_safari;
    else if (strstr(achp_useragent, "Trident") != NULL) 
      adsp_out->iec_browser = ied_browser_msie;
    else { 
      adsp_out->iec_browser  = ied_browser_unknown;
      return -1;
    }
  return 1;
}

// Parse platform string received from browser and determine the user's OS
static int m_parse_platform(struct dsd_browser_data *adsp_out, const char *achp_platform) {
  if (strstr(achp_platform, "Android") != NULL) 
    adsp_out->iec_platform = ied_platform_android;  
  else if (
    strstr(achp_platform, "FreeBSD") != NULL) 
    adsp_out->iec_platform = ied_platform_freebsd;  
  else if (
    strstr(achp_platform, "iPad") != NULL || 
    strstr(achp_platform, "iPhone") != NULL || 
    strstr(achp_platform, "iPod") != NULL ) 
    adsp_out->iec_platform = ied_platform_ios;  
  else if (strstr(achp_platform, "Linux") != NULL)
    adsp_out->iec_platform = ied_platform_linux;  
  else if (strstr(achp_platform, "Mac") != NULL)
    adsp_out->iec_platform = ied_platform_mac;  
  else if (strstr(achp_platform, "SunOS") != NULL)
    adsp_out->iec_platform = ied_platform_sun;  
  else if (strstr(achp_platform, "Win") != NULL)
    adsp_out->iec_platform = ied_platform_windows;  
  else {
    adsp_out->iec_platform = ied_platform_unknown;
    return -1;
  }
  return 1;
}

#endif