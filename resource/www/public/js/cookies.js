/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|    cookies.js                                                       |*/
/*|       a javascript tool to create and use cookies                   |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|    extracted from admin.js by:  Maxim Gurov, March 2012             |*/
/*|    originally written by:       Michael Jakobs, May 2010            |*/
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

/*+---------------------------------------------------------------------+*/
/*| globals:                                                            |*/
/*+---------------------------------------------------------------------+*/
var dsg_cookies = new dsd_cookie();

/*+---------------------------------------------------------------------+*/
/*| cookie parser:                                                      |*/
/*+---------------------------------------------------------------------+*/
function dsd_cookie() {
    this.dsc_cookies = new Array();


    /**
    * public function m_init
    * parse cookies document object and store them in our array
    *
    * @return  nothing
    */
    this.m_init = function () {
        // initialize some variables:
        var strrl_all;
        var strrl_cur;
        var inl_pos;
        var dsl_element;

        strrl_all = document.cookie.split(";");

        for (inl_pos = 0; inl_pos < strrl_all.length; inl_pos++) {
            strrl_cur = strrl_all[inl_pos].split("=");

            // create element:
            dsl_element = new Object();
            dsl_element.name = strrl_cur[0].replace(/^\s+|\s+$/g, '');
            dsl_element.value = strrl_all[inl_pos].substr(strrl_cur[0].length + 1);

            this.dsc_cookies.push(dsl_element);
        }
    } // end of m_init


    /**
    * public function m_get
    * get value from cookie for given name
    *
    * @param[in]   string  str_name    name of search cookie
    * @return      string              value of cookie
    *                                  "" if not found
    */
    this.m_get = function (str_name) {
        // initialize some variables:
        var inl_pos;

        for (inl_pos = 0; inl_pos < this.dsc_cookies.length; inl_pos++) {
            if (this.dsc_cookies[inl_pos].name == str_name) {
                return this.dsc_cookies[inl_pos].value;
            }
        }
        return "";
    } // end of m_get


    /**
    * public function m_set
    * set new cookie
    *
    * @param[in]   string  str_name    name of cookie
    * @param[in]   string  str_value   value of cookie
    * @return      bool                true = success
    */
    this.m_set = function (str_name, str_value) {
        document.cookie = str_name + "=" + str_value;

        // create new array:
        this.dsc_cookies = new Array();
        this.m_init();

        return (this.m_get(str_name) == str_value);
    } // end of m_set
} // end of dsd_cookie