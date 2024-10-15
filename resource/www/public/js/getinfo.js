function m_get_browser() {
   var browser=navigator.appName.toLowerCase();
   var details=navigator.userAgent.toLowerCase();
   var platform=navigator.platform.toLowerCase();

   var browser_name= browser;
   var platform_name= platform;
   if (navigator) {
      //Check for Internet Explorer
      if (browser.indexOf("microsoft") != -1) {browser_name="Internet Explorer"}
      else
      //Check for Firefox
      if(details.indexOf("firefox") != -1) {browser_name="Firefox"}
      else
      //Check for Safari browsers
      if(details.indexOf("safari") != -1) {browser_name="Safari"}
      else
      //Check for Mozilla browsers
      if(details.indexOf("netscape") != -1) {browser_name="Netscape"}
      else
      //Check for Opera browsers
      if(details.indexOf("opera") != -1) {browser_name="Opera"}
      else
      //Check for Konqueror browsers
      if(details.indexOf("konqueror") != -1) {browser_name="Konqueror"}

      return (browser_name);
   }
}

var bo_is_win= false;
var bo_is_vista= false;

function m_get_os() {
   var browser=navigator.appName.toLowerCase();
   var details=navigator.userAgent.toLowerCase();
   var platform=navigator.platform.toLowerCase();

   var browser_name= browser;
   var platform_name= platform;
   if (navigator) {
      if(platform.indexOf("win") != -1) {
         platform_name="Windows ";
         bo_is_win= true;
         if (details.indexOf("windows nt")   	  !=-1)
         {
            if (details.indexOf("windows nt 6.0")   	 !=-1) {platform_name+= "Vista"; bo_is_vista= true;}
            else if (details.indexOf("windows nt 6")   !=-1) {platform_name+= "Vista or higher"; bo_is_vista= true;}
            else if (details.indexOf("windows nt 7")   !=-1) {platform_name+= "Vista or higher"; bo_is_vista= true;}
            else if (details.indexOf("windows nt 10")  !=-1) {platform_name+= "Vista or higher"; bo_is_vista= true;}
            else if (details.indexOf("windows nt 5.2") !=-1) platform_name+= "Server 2003";
            else if (details.indexOf("windows nt 5.1") !=-1) platform_name+= "XP";
            else if (details.indexOf("windows nt 5.0") !=-1) platform_name+= "2000";
            else if (details.indexOf("windows nt 5")   !=-1) platform_name+= "2000 and higher";
            else if (details.indexOf("windows nt 4")   !=-1) platform_name+= "NT";
         }
         else if (details.indexOf("9x")             !=-1) platform_name+= "Millennium";
         else if (details.indexOf("windows me")!=-1) platform_name+= "Millennium";
         else if (details.indexOf("win16")     !=-1) platform_name+= "3.1";
         else if (details.indexOf("95")        !=-1) platform_name+= "95";
         else if (details.indexOf("98")        !=-1) platform_name+= "98";
         else if (details.indexOf("xp")        !=-1) platform_name+= "XP";
         else if (details.indexOf("windows ce")!=-1) platform_name+= "CE";
         if(platform.indexOf("64") != -1) platform_name+= " 64 Bit";
      }
      else
      if(platform.indexOf("linux") != -1) {
         platform_name="Linux";
      }
      else
      if(platform.indexOf("iphone") != -1) {
         platform_name="iPhone";
      }
      else
      if(platform.indexOf("ipod") != -1) {
         platform_name="iPod";
      }
      else
      if(platform.indexOf("mac") != -1) {
         platform_name="Macintosh";
      }
 //     alert(platform_name);
      return (platform_name);
   }
}
