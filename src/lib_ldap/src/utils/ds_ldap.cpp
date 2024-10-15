/*|   J.Frank  20.04.11    The global variables hstrg_attrname_groupmembers and                    |*/
/*|                        hstrg_attrname_groupmembersin were wrongly initialised.                 |*/

#define HOB_CONTR_TIMER

#if defined WIN32 || defined WIN64
    #include <winsock2.h>
    #include <Ws2tcpip.h>
    #include <windows.h>
    #pragma warning(disable:4996)
#else
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <errno.h>
    #include <hob-unix01.h>
#endif
#ifdef HL_FREEBSD
#include <sys/socket.h>
#endif
#include <types_defines.h>
#include <ds_attribute_string.h>
#include "hob-xslcontr.h"
#include "hob-netw-01.h"
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H
#include "hob-wsppriv.h"
#include <hob-avl03.h>
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"
#include "ds_ldap.h"
#include <rdvpn_globals.h>
#include <ds_xml.h>
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H


/*+---------------------------------------------------------------------+*/
/*| Names of BINARY attributes in LDAP:                                 |*/
/*+---------------------------------------------------------------------+*/
const char* achr_binary_attrs[] = {
    "userCertificate"     , "photo"               , "personalSignature"      , "audio"    ,
    "jpegPhoto"           , "javaSerializedData"  , "thumbnailPhoto"         , "thumbnailLogo"        ,
    "userPassword"        , "cACertificate"       , "authorityRevocationList", "certificateRevocationList"  ,
    "crossCertificatePair", "x500UniqueIdentifier", NULL
};


/*
In LDAP, if one of the following characters appears in the name, then it must be preceeded by the escape character, the backslash character ("\"): 
 - A space or "#" character occurring at the beginning of the string 
 - A space character occurring at the end of the string 
 - One of the characters ",", "+", """, "\", "<", ">" or ";" 
*/
/* Some rules concerning Escaping for this LDAP tool (agreed with J.Lauenstein):
- Escaped strings is necessary, when DNs or parts of them are under work.
- The LDAP server always returns escaped strings.
- When the user enters a complete DN for logon, the user has to correctly escape.
- User's name/DN will be displayed including the escape characters.
*/


ds_ldap::ds_ldap()
{
    memset( (void *)&adsc_co_ldap, (int)0, (size_t)sizeof(struct dsd_co_ldap_1) );

    bog_sysinfo_done = false;
}

ds_ldap::~ds_ldap(void)
{
   // m_close();
}

void ds_ldap::m_init( ds_wsp_helper* adsl_wsp_helper )
{
    ads_wsp_helper = adsl_wsp_helper;
    hstr_last_error.m_init(ads_wsp_helper);
    if (hstr_last_error.m_get_ptr() == NULL) {
        hstr_last_error.m_write("");
    }
    hstr_our_dn.m_init(ads_wsp_helper);
    if (hstr_our_dn.m_get_ptr() == NULL) {
        hstr_our_dn.m_write("");
    }
    hstrg_address.m_init(ads_wsp_helper);
    if (hstrg_address.m_get_ptr() == NULL) {
        hstrg_address.m_write("");
    }
    hstrg_base.m_init(ads_wsp_helper);
    if (hstrg_base.m_get_ptr() == NULL) {
        hstrg_base.m_write("");
    }
    hstrg_user_prefix.m_init(ads_wsp_helper);
    if (hstrg_user_prefix.m_get_ptr() == NULL) {
        hstrg_user_prefix.m_write("");
    }
    hstrg_attrname_group.m_init(ads_wsp_helper);
    if (hstrg_attrname_group.m_get_ptr() == NULL) {
        hstrg_attrname_group.m_write("");
    }
    hstrg_attrname_groupmembers.m_init(ads_wsp_helper);
    if (hstrg_attrname_groupmembers.m_get_ptr() == NULL) {
        hstrg_attrname_groupmembers.m_write(""); // JF 20.04.11 hstrg_user_prefix
    }
    hstrg_attrname_groupmembersin.m_init(ads_wsp_helper);
    if (hstrg_attrname_groupmembersin.m_get_ptr() == NULL) {
        hstrg_attrname_groupmembersin.m_write(""); // JF 20.04.11 hstrg_user_prefix
    }
    hstrg_searchuser.m_init(ads_wsp_helper);
    if (hstrg_searchuser.m_get_ptr() == NULL) {
        hstrg_searchuser.m_write("");
    }

    // JF 04.03.10 Fetching of sysinfo must be done AFTER we selected the LDAP server. Therefore this
    // call was moved into m_bind(), which is called by sdh_ea_ldap.m_connect(), which selects the LDAP server.
    //if (bog_sysinfo_required && !bog_sysinfo_done) { // We must read information about the LDAP server (e.g. the baseDN)
    //    bog_sysinfo_done = (m_get_sysinfo() == SUCCESS);
    //}
}


void ds_ldap::m_reset() {
    // Close the current open connection.
    m_close();

    hstr_last_error     .m_reset();
    hstr_our_dn         .m_reset();
    hstrg_address       .m_reset();
    hstrg_base          .m_reset();
    hstrg_user_prefix   .m_reset();
    hstrg_attrname_group.m_reset();
    hstrg_attrname_groupmembers  .m_reset(); // JF 20.04.11 hstrg_user_prefix
    hstrg_attrname_groupmembersin.m_reset(); // JF 20.04.11 hstrg_user_prefix
    hstrg_searchuser    .m_reset();

    m_init_ldap(false);
    bog_sysinfo_done = false;
    memset((void *)&adsc_co_ldap, (int)0, (size_t)sizeof(struct dsd_co_ldap_1));
}


void ds_ldap::m_init_ldap(bool bol_insert_oc) {
    bog_insert_oc = bol_insert_oc;
}


const ds_hstring& ds_ldap::m_get_last_error() {
    return hstr_last_error;
}

const ds_hstring& ds_ldap::m_get_user_dn() {
    return hstr_our_dn;
}

int ds_ldap::m_get_srv_type() {
    return ing_ldap_srv_type;
}

int ds_ldap::m_get_address(ds_hstring* ahstr) {
    if (ahstr == NULL) {
        return 1;
    }
    ahstr->m_set(hstrg_address);
    return SUCCESS;
}

int ds_ldap::m_get_base(ds_hstring* ahstr) {
    if (ahstr == NULL) {
        return 1;
    }
    ahstr->m_set(hstrg_base);
    return SUCCESS;
}

int ds_ldap::m_get_searchuser(ds_hstring* ahstr) {
    if (ahstr == NULL) {
        return 1;
    }
    ahstr->m_set(hstrg_searchuser);
    return SUCCESS;
}

int ds_ldap::m_get_userprefix(ds_hstring* ahstr) {
    if (ahstr == NULL) {
        return 1;
    }
    ahstr->m_set(hstrg_user_prefix);
    return SUCCESS;
}

// Get the attribute name, which holds the members of a group.
int ds_ldap::m_get_groupmembers(ds_hstring* ahstr) {
    if (ahstr == NULL) {
        return 1;
    }
    ahstr->m_set(hstrg_attrname_groupmembers);
    return SUCCESS;
}

// Get the attribute name, which holds the groups, where a user is member in. This is not supported by all LDAP servers.
int ds_ldap::m_get_groupmembersin(ds_hstring* ahstr) {
    if (ahstr == NULL) {
        return 1;
    }
    ahstr->m_set(hstrg_attrname_groupmembersin);
    return SUCCESS;
}

int ds_ldap::m_escape(ds_hstring* ahstr_to_escape, ds_hstring* ahstr_target) {
    // The length of the string, on which we are working, can be changed.
    // So we must copy the data to a new string.

    if ( (ahstr_target == NULL) || (ahstr_target->m_get_ptr() == NULL) ) {
        return 1;
    }
    if ( (ahstr_to_escape == NULL) || (ahstr_to_escape->m_get_ptr() == NULL) ) {
        return 2;
    }

    if (ahstr_to_escape->m_get_len() == 0) { // can be empty!
        return SUCCESS;
    }

    char ch;
    for (int i=0; i<ahstr_to_escape->m_get_len(); i++) {
        ch = (*ahstr_to_escape)[i];

        // Escape a space or "#" character occurring at the beginning of the string
        if ( (i == 0) && ((ch == ' ') || (ch == '#')) ) {
            ahstr_target->m_write("\\");
            ahstr_target->m_write(&ch, 1);
            continue;
        }

        // Escape a space character occurring at the end of the string
        if ( (i == ahstr_to_escape->m_get_len()-1) && (ch == ' ') ) {
            ahstr_target->m_write("\\ ");
            continue;
        }

        // Escape the characters ",", "+", """, "\", "<", ">" or ";"
        // ATTENTION: 1) This would escape commas, which are working as usual separators, too.
        //            2) Be prepared, that e.g. commas are already escaped!
        //if ( (ch == ',') || (ch == '+') || (ch == '"') || (ch == '\\') || (ch == '<') || (ch == '>') || (ch == ';') ) {
        //    ahstr_target->m_write("\\");
        //    ahstr_target->m_write(&ch, 1);
        //    continue;
        //}

        // do not change this char
        ahstr_target->m_write(&ch, 1);
    }

    return SUCCESS;
}


// similar to LDAPSet.hlGetOCID(Attributes resultAttr)
char ds_ldap::m_get_oc_id(const ds_attribute_string* adsl_attr) {
    if (adsl_attr == NULL) {
        ads_wsp_helper->m_log(ied_sdh_log_error, "HLDAE222E: m_get_oc_id() called with invalid parameter.");
        return C_CHECK; // default
    }

    bool bo_gateway = false;
    bool bo_computer = false;

    // search with highest priority for object class "hobgateway" or computer
    const ds_hvector<ds_hstring>& ds_values = adsl_attr->m_get_values();
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ds_values)) {
        const ds_hstring& hstr_oc = HVECTOR_GET(adsl_cur);
        if (hstr_oc.m_equals_ic(LDAP_HOB_GATEWAY)) {
            bo_gateway = true;
        }
        if (hstr_oc.m_equals_ic(LDAP_COMPUTER)) {
            bo_computer = true;
        }
    }

    // search with highest priority for object class "hobgateway" or computer
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, ds_values)) {
        const ds_hstring& hstr_oc = HVECTOR_GET(adsl_cur);
        if (hstr_oc.m_equals_ic(LDAP_ORG)) { // "organization"
            return C_COMPANY;
        }
        if (hstr_oc.m_equals_ic(LDAP_CONTAINER)) { // "container"
            return C_CONTAINER;
        }
        if (hstr_oc.m_equals_ic(LDAP_OUNIT)) { // "organizationalUnit"
            return C_DEPART;
        }
        if (hstr_oc.m_equals_ic(hstrg_attrname_group)) { // e.g. "groupofuniquenames"
            return C_GROUP;
        }
        if (hstr_oc.m_equals_ic(LDAP_PERSON)) { // it's a person (or hobgateway or computer)
            if (bo_gateway || bo_computer) {
                return C_OBJECT;
            }
            return C_USER;
        }
        if (hstr_oc.m_equals_ic(LDAP_EOBJECT)) { // "extensibleObject"
            return C_OBJECT;
        }
        //inception AK
        if ( hstr_oc.m_equals_ic(LDAP_DOMAIN) ) {
            return C_DOMAIN;
        }
        //end AK
    }

    // We cannot resolve any of the object classes but the one 'hobgateway' -> we assume it is an object
    if (bo_gateway) {
        return C_OBJECT;
    }

    return C_CHECK; // default
}

int ds_ldap::m_close() {
    ads_wsp_helper->m_log(ied_sdh_log_details, "HLDAD201D: m_close().");

    adsc_co_ldap.iec_co_ldap = ied_co_ldap_close;
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if ( (bo_ret == false) || (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) ) {
        hstr_last_error.m_set("HLDAE666E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_close) failed.");
        if (bo_ret == false) {
            hstr_last_error.m_write(" Method returned false. Check, whether the server is running.");
			ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 1;
        }
        if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
            hstr_last_error.m_writef(" Error %d.", adsc_co_ldap.iec_ldap_resp);
            if (adsc_co_ldap.ac_errmsg != NULL) {
                if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                    hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
                }
                else {
                    hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
                }
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    return SUCCESS;
}


// Method does not write errors to log file.
// negative return value: A fatal error occured. We cannot go on.
int ds_ldap::m_get_sysinfo() {
    ads_wsp_helper->m_log(ied_sdh_log_details, "HLDAD001D: m_get_sysinfo().");

    adsc_co_ldap.iec_co_ldap = ied_co_ldap_get_sysinfo;
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if ( (bo_ret == false) || (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) ) {
        hstr_last_error.m_set("HLDAE667E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_sysinfo) failed.");
        if (bo_ret == false) {
            hstr_last_error.m_write(" Method returned false. Check, whether the server is running.");
            return 1;
        }
        if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
            hstr_last_error.m_writef(" Error %d.", adsc_co_ldap.iec_ldap_resp);
            if (adsc_co_ldap.ac_errmsg != NULL) {
                if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                    hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
                }
                else {
                    hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
                }
            }
        }
        return 2;
    }
    if (adsc_co_ldap.adsc_sysinfo == NULL) {
        hstr_last_error.m_set("HLDAE538E: LDAP response does not contain system info.");
        return 3;
    }
    if (adsc_co_ldap.adsc_sysinfo->adsc_base_dn == NULL) {
        hstr_last_error.m_set("HLDAE539E: LDAP response does not contain base DN.");
        return 4;
    }
    // up to now we support only charset UTF8 in the LDAP-response
    if (adsc_co_ldap.adsc_sysinfo->adsc_base_dn->iec_chs_val != ied_chs_utf_8) {
        hstr_last_error.m_set("HLDAE578E: Base DN of system info is not in UTF8.");
        return 5;
    }

    // SearchUser
    hstrg_searchuser.m_set(adsc_co_ldap.adsc_sysinfo->ac_admin, adsc_co_ldap.adsc_sysinfo->imc_len_admin);
    ads_wsp_helper->m_logf(ied_sdh_log_info, "HLDAI002I: SearchUser: %s.", hstrg_searchuser.m_get_ptr());

    // Server base
    // Attention: Some LDAP servers will give out more bases. In this case J.Lauenstein will deliver the one, which is specified in wsp.xml.
    // If the specified DN does not match any of the returned bases, all bases will be returned by J.Lauenstein.
	if (adsc_co_ldap.adsc_sysinfo->adsc_base_dn_conf->adsc_next_val != NULL) { // more bases are returned -> error
        hstr_last_error.m_set("HLDAE278E: No base DN conf is returned.");
        return -1; // negative: A fatal error occured. We cannot go on.
    }
    //hstrg_base.m_write(adsc_co_ldap.adsc_sysinfo->adsc_base_dn->ac_val, adsc_co_ldap.adsc_sysinfo->adsc_base_dn->imc_len_val, false);
	if ( adsc_co_ldap.adsc_sysinfo->adsc_base_dn_def != NULL ) {
		hstrg_base.m_set(adsc_co_ldap.adsc_sysinfo->adsc_base_dn_def->ac_val, adsc_co_ldap.adsc_sysinfo->adsc_base_dn_def->imc_len_val);
	} else {
		hstrg_base.m_set(adsc_co_ldap.adsc_sysinfo->adsc_base_dn_conf->ac_val, adsc_co_ldap.adsc_sysinfo->adsc_base_dn_conf->imc_len_val);
	}
    ads_wsp_helper->m_logf(ied_sdh_log_info, "HLDAI003I: Server base: %s.", hstrg_base.m_get_ptr());

    // Server type
    ing_ldap_srv_type = adsc_co_ldap.adsc_sysinfo->iec_type;
    ads_wsp_helper->m_logf(ied_sdh_log_info, "HLDAI003I: Server type: %d.", ing_ldap_srv_type);

    // Server address
    // The structures dsd_target_ineta_1 is followed by a structure dsd_ineta_single_1,
    // which is followed by the corresponding INETA. dsd_ineta_single_1 contains family IPV4 / IPV6 and the length of following address.
    dsd_target_ineta_1* adsl_inet = adsc_co_ldap.adsc_sysinfo->adsc_target_ineta;
    adsl_inet = adsl_inet + 1; // hop behind this structure
    dsd_ineta_single_1* adsl_single = ((dsd_ineta_single_1*)adsl_inet);
    dsd_ineta_single_1* adsl_behind = adsl_single + 1; // hop behind this structure
    char* ach_address = (char*)adsl_behind; // here is the info!!

    hstrg_address.m_reset();
    switch (adsl_single->usc_family) {
        case AF_INET: { // IPv4
            if (adsl_single->usc_length != 4) {
                hstr_last_error.m_reset();
                hstr_last_error.m_writef("HLDAE565E: Unexpected length information %d instead of %d.", adsl_single->usc_length, 4);
                return 42;
            }
            hstrg_address.m_writef( "%d.%d.%d.%d",
                                    (unsigned char)ach_address[0],
                                    (unsigned char)ach_address[1],
                                    (unsigned char)ach_address[2],
                                    (unsigned char)ach_address[3] );
            break;
        }
        case AF_INET6: { // IPv6
            if (adsl_single->usc_length != 16) {
                hstr_last_error.m_reset();
                hstr_last_error.m_writef("HLDAE566E: Unexpected length information %d instead of %d.", adsl_single->usc_length, 16);
                return 43;
            }
            hstrg_address.m_writef( "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                               (unsigned char)ach_address[ 0],
                               (unsigned char)ach_address[ 1],
                               (unsigned char)ach_address[ 2],
                               (unsigned char)ach_address[ 3],
                               (unsigned char)ach_address[ 4],
                               (unsigned char)ach_address[ 5],
                               (unsigned char)ach_address[ 6],
                               (unsigned char)ach_address[ 7],
                               (unsigned char)ach_address[ 8],
                               (unsigned char)ach_address[ 9],
                               (unsigned char)ach_address[10],
                               (unsigned char)ach_address[11],
                               (unsigned char)ach_address[12],
                               (unsigned char)ach_address[13],
                               (unsigned char)ach_address[14],
                               (unsigned char)ach_address[15] );
            break;
        }
        default: {
            hstr_last_error.m_reset();
            hstr_last_error.m_writef("HLDAE567E: Unknown adress family %d.", adsl_single->usc_family);
            return 41;
        }
    }
    ads_wsp_helper->m_logf(ied_sdh_log_info, "HLDAD004D: Server address: %s.", hstrg_address.m_get_ptr());

    // Template info
    dsd_ldap_template* adsl_tpl = adsc_co_ldap.adsc_sysinfo->adsc_ldap_template;
    hstrg_attrname_group.m_set          (adsl_tpl->achc_group_attr , adsl_tpl->imc_len_group_attr); // Attribute name for 'group'
    hstrg_attrname_groupmembers.m_set   (adsl_tpl->achc_member_attr, adsl_tpl->imc_len_member_attr); // Attribute name: which members a group has
    hstrg_attrname_groupmembersin.m_set (adsl_tpl->achc_mship_attr , adsl_tpl->imc_len_mship_attr); // Attribute name: in which group a user is member in
    hstrg_user_prefix.m_set             (adsl_tpl->achc_upref      , adsl_tpl->imc_len_upref); // User's prefix

    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD006D: Attribute name for groups: %s.", hstrg_attrname_group.m_get_ptr()); 
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD007D: Attribute name, which members a group has: %s.", hstrg_attrname_groupmembers.m_get_ptr());
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD008D: Attribute name, in which group a user is member in: %s.", hstrg_attrname_groupmembersin.m_get_ptr());
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD009D: User prefix: %s.", hstrg_user_prefix.m_get_ptr());

    return SUCCESS;
}



/**
 * Retrieve the time, when the DN's password will expire.
 *
 * @param[in] ahstr_dn DN, for which the expiration time shall be retrieved.
 * @param[out] adsl_ldap_pwd Structure will get filled with the remaining time.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 * @author: Joachim Frank
*/
int ds_ldap::m_get_pw_expire_time(const ds_hstring* ahstr_dn, dsd_ldap_pwd* adsl_ldap_pwd) {
    ads_wsp_helper->m_log(ied_sdh_log_info, "HLDAI430I: m_get_pw_expire_time().");
    if ( (ahstr_dn == NULL) || (adsl_ldap_pwd == NULL) ) {
        hstr_last_error.m_set("HLDAE431E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_check_pwd_age) failed because of invalid parameters.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    
    adsc_co_ldap.ac_dn         = const_cast<char*>(ahstr_dn->m_get_ptr());
    adsc_co_ldap.imc_len_dn    = ahstr_dn->m_get_len();
    adsc_co_ldap.iec_chs_dn    = ied_chs_utf_8;
    adsc_co_ldap.adsc_pwd_info = adsl_ldap_pwd;
    adsc_co_ldap.iec_co_ldap   = ied_co_ldap_check_pwd_age;
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if ( (bo_ret == false) || (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) ) {
        hstr_last_error.m_set("HLDAE432E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_check_pwd_age) failed.");
        if (bo_ret == false) {
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 2;
        }
        if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
            hstr_last_error.m_writef(" Error %d.", adsc_co_ldap.iec_ldap_resp);
            if (adsc_co_ldap.ac_errmsg != NULL) {
                if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                    hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
                }
                else {
                    hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
                }
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 3;
    }

    return SUCCESS;
}



/**
 * Retrieve the DN of the user, which is currently logged on.
 *
 * @param[out] abo_is_bound true: There is a binding. ahstr_bind_dn contains the DN. false: no binding found.
 * @param[out] ahstr_bind_dn DN of the logged user. Undefined, when no binding exists.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 * @author: Joachim Frank
*/
int ds_ldap::m_get_bind_context(bool* abo_is_bound, ds_hstring* ahstr_bind_dn) {
    ads_wsp_helper->m_log(ied_sdh_log_info, "HLDAI120I: m_get_bind_context().");
    if ( (abo_is_bound == NULL) || (ahstr_bind_dn == NULL) ) {
        hstr_last_error.m_set("HLDAE457E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_bind) failed because of invalid parameters.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    
    if (!bog_sysinfo_done) { // We must read information about the LDAP server (e.g. the baseDN)
        int inl_ret = m_get_sysinfo();
        if (inl_ret < 0) { // negative: A fatal error occured. We cannot go on.
            // The error message is not yet written to log file.
            ads_wsp_helper->m_logf(ied_sdh_log_error, "HLDAE478E: Bind failed, because m_get_sysinfo() failed with error %d. Details: %.*s.",
				inl_ret, hstr_last_error.m_get_len(), hstr_last_error.m_get_ptr());
            return 100;
        }
        bog_sysinfo_done = (inl_ret == SUCCESS);
    }

    adsc_co_ldap.iec_co_ldap    = ied_co_ldap_get_bind;
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if ( (bo_ret == false) || (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) ) {
        hstr_last_error.m_set("HLDAE467E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_bind) failed.");
        if (bo_ret == false) {
            hstr_last_error.m_write(" Method returned false. Check, whether the server is running.");
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 2;
        }
        if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
            hstr_last_error.m_writef(" Error %d.", adsc_co_ldap.iec_ldap_resp);
            if (adsc_co_ldap.ac_errmsg != NULL) {
                if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                    hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
                }
                else {
                    hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
                }
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 3;
    }

    if (adsc_co_ldap.iec_ldap_resp == ied_ldap_no_bind) {
        *abo_is_bound = false;
        return SUCCESS;
    }

    // There is a binding. Fill the according return values.
    *abo_is_bound = true;
    ahstr_bind_dn->m_set(adsc_co_ldap.ac_userid, adsc_co_ldap.imc_len_userid);

    return SUCCESS;
}

/**
 * Connect to LDAP server and do a logon according to the selected mode.
 * E.g. ied_ldap_auth::ied_auth_user means a logon as SearchAdmin and a search for the user
 * name (with/without LDAP prefix). Then a bind is performed with the resolved DN and the password.
 *
 * @param[in] hstr_userid name of the user (with/without LDAP prefix) or the whole user's DN
 * @param[in] ahstr_password Password of the user. Can be NULL.
 * @param[in] in_mode Mode, how the logon to LDAP shall be established (e.g. ied_ldap_auth::ied_auth_user).
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 *         Return value LDAP_USER_MUST_CHANGE_PW signals, that the user has to reset his password!
*/
int ds_ldap::m_bind(const ds_hstring* ahstr_userid, const ds_hstring* ahstr_password, ied_auth_ldap_def in_mode) {
    return m_bind(ahstr_userid, ahstr_password, NULL, in_mode);
}


/**
 * Connect to LDAP server and do a logon according to the selected mode.
 * E.g. ied_ldap_auth::ied_auth_user means a logon as SearchAdmin and a search for the user
 * name (with/without LDAP prefix). Then a bind is performed with the resolved DN and the password.
 *
 * @param[in] hstr_userid name of the user (with/without LDAP prefix) or the whole user's DN
 * @param[in] ahstr_password Password of the user. Can be NULL.
 * @param[in] ahstr_base_add This will extend the LDAP's base to have something like a 'sub-base' (represents the domains). Can be NULL.
 * @param[in] in_mode Mode, how the logon to LDAP shall be established (e.g. ied_ldap_auth::ied_auth_user).
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 *         Return value LDAP_USER_MUST_CHANGE_PW signals, that the user has to reset his password!
*/
int ds_ldap::m_bind(const ds_hstring* ahstr_userid, const ds_hstring* ahstr_password,
                    const ds_hstring* ahstr_base_add, ied_auth_ldap_def in_mode) {
    const char* ach_userid = NULL;
    int in_len_userid = 0;
    if (ahstr_userid != NULL) {
        ach_userid    = ahstr_userid->m_get_ptr();
        in_len_userid = ahstr_userid->m_get_len();
    }
    const char* ach_password = NULL;
    int in_len_password = 0;
    if (ahstr_password != NULL) {
        ach_password    = ahstr_password->m_get_ptr();
        in_len_password = ahstr_password->m_get_len();
    }
    const char* ach_base_add = NULL;
    int in_len_base_add = 0;
    if (ahstr_base_add != NULL) {
        ach_base_add    = ahstr_base_add->m_get_ptr();
        in_len_base_add = ahstr_base_add->m_get_len();
    }
    return m_bind(false, ach_userid, in_len_userid, ach_password, in_len_password,
                  ach_base_add, in_len_base_add, in_mode);
}


/**
 * This interface uses char-pointer and length-info instead of ds_hstring. See the ds_hstring-API for a detailed description. 
 * @author: Joachim Frank
*/
int ds_ldap::m_bind(const char* ach_userid, int in_len_userid, const char* ach_password, int in_len_password, ied_auth_ldap_def in_mode) {
    return m_bind(false, ach_userid, in_len_userid, ach_password, in_len_password, NULL, 0, in_mode);
}


/**
 * This interface uses char-pointer and length-info instead of ds_hstring.
 * @author: Joachim Frank
*/
int ds_ldap::m_bind(const char* ach_userid, int in_len_userid, const char* ach_password, int in_len_password,
                    const char* ach_base_add, int in_len_base_add, ied_auth_ldap_def in_auth_mode) {
    return m_bind(false, ach_userid, in_len_userid, ach_password, in_len_password,
                  ach_base_add, in_len_base_add, in_auth_mode);
}


/**Do a bind to LDAP as SearchAdmin. Then do NOTHING ELSE (e.g. do not search for a user).
*/
int ds_ldap::m_simple_bind() {
        return m_bind(true, NULL, 0, NULL, 0, NULL, 0, ied_auth_admin);
}


/**
 * Connect to LDAP server and do a logon according to the selected mode.
 * E.g. ied_ldap_auth::ied_auth_user means a logon as SearchAdmin and a search for the user
 * name (with/without LDAP prefix). Then a bind is performed with the resolved DN and the password.
 *
 * @param[in] bo_simple_bind Do a bind to LDAP as SearchAdmin. Then do NOTHING ELSE (e.g. do not search for a user).
 * @param[in] ach_userid name of the user (with/without LDAP prefix) or the whole user's DN. Can be NULL, if bo_simple_bind is true.
 * @param[in] in_len_userid Length of userid.
 * @param[in] ach_password Password of the user. Can be NULL.
 * @param[in] in_len_password Length of password.
 * @param[in] ach_base_add This will extend the LDAP's base to have something like a 'sub-base' (represents the domains; called 'additional base'). Can be NULL.
 * @param[in] in_len_base_add Length of 'additional base'.
 * @param[in] in_mode Mode, how the logon to LDAP shall be established (e.g. ied_ldap_auth::ied_auth_user).
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 *         Return value LDAP_USER_MUST_CHANGE_PW signals, that the user has to reset his password!
*/
int ds_ldap::m_bind(bool bo_simple_bind, const char* ach_userid, int in_len_userid, const char* ach_password, int in_len_password,
                    const char* ach_base_add, int in_len_base_add, ied_auth_ldap_def in_auth_mode) {
    if (!bog_sysinfo_done) { // We must read information about the LDAP server (e.g. the baseDN)
        int inl_ret = m_get_sysinfo();
        if (inl_ret < 0) { // negative: A fatal error occured. We cannot go on.
            // The error message is not yet written to log file.
            ads_wsp_helper->m_logf(ied_sdh_log_error, "HLDAE477E: Bind failed, because m_get_sysinfo() failed with error %d. Details: %.*s.", // JF 02.08.10: HLDAE478E -> HLDAE477E
				inl_ret, hstr_last_error.m_get_len(), hstr_last_error.m_get_ptr());
            return 100;
        }
        bog_sysinfo_done = (inl_ret == SUCCESS);
    }

    adsc_co_ldap.iec_co_ldap            = ied_co_ldap_bind;
    adsc_co_ldap.iec_ldap_auth          = in_auth_mode;
    adsc_co_ldap.ac_passwd              = NULL;
    adsc_co_ldap.imc_len_passwd         = 0;
    adsc_co_ldap.iec_chs_passwd         = ied_chs_utf_8;
    adsc_co_ldap.dsc_add_dn.ac_str      = NULL;
    adsc_co_ldap.dsc_add_dn.imc_len_str = 0;
    adsc_co_ldap.dsc_add_dn.iec_chs_str = ied_chs_utf_8;

    ds_hstring hstr_username(ads_wsp_helper, "");
    if (bo_simple_bind == false) {
        if ( (ach_userid == NULL) || (in_len_userid < 1) ) {
            hstr_last_error.m_set("HLDAE476E: Bind failed. No user is specified."); // JF 02.08.10: HLDAE478E -> HLDAE476E
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 1;
        }
        ads_wsp_helper->m_logf(ied_sdh_log_info, "HLDAI001I: Bind user '%.*s' with mode %d.", in_len_userid, ach_userid, in_auth_mode);

        // 28.01.10 Ticket[18563]: If a user name with a '*' is entered into the logon dialog, the resulting search will be done
        // with the wild card '*'. To prevent the wild card, we must escape the '*'.
        hstr_username.m_write(ach_userid, in_len_userid);
        if (hstr_username.m_find_first_of("*") != -1) {
            // Check whether all occuring '*' are already escaped. If not, then escape it.
            ds_hstring ds_result(ads_wsp_helper, "");
            char ch_curr, ch_prev = ' ';
            for (int i=0; i<hstr_username.m_get_len(); i++) {
                ch_curr = hstr_username[i];
                if (ch_curr == '*') {
                    if ( (i==0)                // first character: is not escaped -> escape it
                    ||   (ch_prev != '\\') ) { // previous character was not the escape-character -> escape it
                        ds_result.m_write("\\", 1);
                    }
                }
                ds_result.m_write(&ch_curr, 1);
                ch_prev = ch_curr;
            }
            hstr_username.m_set(ds_result);                
        }

        adsc_co_ldap.ac_userid      = const_cast<char*>(hstr_username.m_get_ptr());
        adsc_co_ldap.imc_len_userid = hstr_username.m_get_len();
        adsc_co_ldap.iec_chs_userid = ied_chs_utf_8;
        if ( (ach_password != NULL) && (in_len_password > 0) ) {
            adsc_co_ldap.ac_passwd      = const_cast<char*>(ach_password);
            adsc_co_ldap.imc_len_passwd = in_len_password;
        }

        // Additional base
        if ( (ach_base_add != NULL) && (in_len_base_add > 0) ) {
            adsc_co_ldap.dsc_add_dn.ac_str      = const_cast<char*>(ach_base_add);
            adsc_co_ldap.dsc_add_dn.imc_len_str = in_len_base_add;
        }
        else {
            adsc_co_ldap.dsc_add_dn.ac_str      = NULL;
            adsc_co_ldap.dsc_add_dn.imc_len_str = 0;
        }
    }   


    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );

    // JF 30.03.11 Reset the additional base, we don't need it any more.
    // Otherwise it will be added by xsldapc01 every time.
    if ( (ach_base_add != NULL) && (in_len_base_add > 0) ) {
        adsc_co_ldap.dsc_add_dn.ac_str      = NULL;
        adsc_co_ldap.dsc_add_dn.imc_len_str = 0;
    }

    if (bo_ret == false) { // Attention: adsc_co_ldap.iec_ldap_resp will get investigated later.
        hstr_last_error.m_set("HLDAE678E: Bind to LDAP failed for user '"); 
        hstr_last_error.m_writef("%.*s': Method returned false. Check, whether the server is running.", adsc_co_ldap.imc_len_userid, adsc_co_ldap.ac_userid);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    // ActiveDirectory: ADS returns the following error, if user has to give a new password
    // "LDAP: error code 49 - 80090308: LdapErr: DSID-0C09030F, comment: AcceptSecurityContext error, data 773, vece"
    // 773 means here, that user must reset his password. Other possible values are:
    // 525 - user not found
    // 52e - invalid credentials
    // 530 - not permitted to logon at this time
    // 531 - not permitted to logon at this workstation 
    // 532 - password expired
    // 533 - account disabled
    // 701 - account expired
    // 773 - user must reset password
    // 775 - user account locked
    // xsldapco1.cpp does the parsing and returns ied_ldap_password_change, if the user has to change his password.
    if (adsc_co_ldap.iec_ldap_resp == ied_ldap_password_change) {
        hstr_last_error.m_set("HLDAW678W: Bind to LDAP for user '");
        hstr_last_error.m_writef("%.*s': User has to reset his password.", adsc_co_ldap.imc_len_userid, adsc_co_ldap.ac_userid);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_warning, hstr_last_error.m_const_str());

#if 0
        // TEST for changing the password
        ds_hstring hstr_pw_new(ads_wsp_helper, "test");
        int in = m_change_pwd(&hstr_username, ahstr_password, &hstr_pw_new);
#endif

        return LDAP_USER_MUST_CHANGE_PW;
    }

    if (bo_simple_bind == true) {
        // TODO: perhaps J.Lauenstein implements something...
        // In case of 'simple bind' no DN is delivered. The return value is ied_ldap_no_results
        if (adsc_co_ldap.iec_ldap_resp == ied_ldap_no_results) {
            // Reset global variable.
            hstr_our_dn.m_reset();
            ads_wsp_helper->m_log(ied_sdh_log_info, "HLDAI710I: Simple bind successful.");
        }
        return SUCCESS;
    }

    if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
        hstr_last_error.m_set("HLDAE638E: Bind to LDAP failed for user '"); 
        hstr_last_error.m_writef("%.*s' with error %d.", adsc_co_ldap.imc_len_userid, adsc_co_ldap.ac_userid, adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 3;
    }


    // The LDAP-module must return the resolved DN.
    if ( (adsc_co_ldap.ac_dn == NULL) || (adsc_co_ldap.imc_len_dn < 0) ) {
        hstr_last_error.m_set("HLDAE573E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_bind) failed. No DN was returned.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 4;
    }

    // up to now we support only charset UTF8 in the LDAP-response
    if (adsc_co_ldap.iec_chs_dn != ied_chs_utf_8) {
        hstr_last_error.m_set("HLDAE578E: LDAP response is not in UTF8.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 5;
    }

    // Write the resolved DN into a global variable.
    hstr_our_dn.m_set(adsc_co_ldap.ac_dn, adsc_co_ldap.imc_len_dn);
    ads_wsp_helper->m_logf(ied_sdh_log_info, "HLDAI010I: User DN resolved as '%s'", hstr_our_dn.m_get_ptr());

    return SUCCESS;
}


/**Get a list of all attributes of a certain DN. The according values can be returned on demand, too.<br>
 * @param adsl_v_attributes [out] Will be filled with the attributes.
 * @param ahstr_dn [in] DN of the item.
 * @param bo_with_val [in] false: only the names of the attributes are retrieved from LDAP server; true: names AND values are retrieved.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_get_attr_list(ds_hvector<ds_attribute_string>* adsl_v_attributes, ds_hstring* ahstr_dn, bool bo_with_val) {
    if (adsl_v_attributes == NULL) {
        hstr_last_error.m_set("HLDAE276E: Invalid parameter to m_get_attr_list.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD129D: m_get_attr_list() for '%s';  bo_with_val %d.", 
        (ahstr_dn==NULL?"<null>":ahstr_dn->m_get_ptr()), bo_with_val);

    if ( (ahstr_dn != NULL) && (ahstr_dn->m_get_len() > 0) ) {
        adsc_co_ldap.ac_dn = const_cast<char*>(ahstr_dn->m_get_ptr());
        adsc_co_ldap.imc_len_dn = ahstr_dn->m_get_len();
    }
    else {
        adsc_co_ldap.ac_dn = NULL;
        adsc_co_ldap.imc_len_dn = 0;
    }
    adsc_co_ldap.iec_co_ldap = ied_co_ldap_get_attrlist;
    adsc_co_ldap.iec_sear_scope = (bo_with_val?ied_sear_baseobject:ied_sear_attronly);

    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD010D: Get attribute list for user: '%s'", (ahstr_dn==NULL?"<logged user>":ahstr_dn->m_get_ptr()));

    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if (bo_ret == false) {
        hstr_last_error.m_set("HLDAE845E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_attrlist) failed: method returned false");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }
    if ((adsc_co_ldap.iec_ldap_resp != ied_ldap_success) && (adsc_co_ldap.iec_ldap_resp != ied_ldap_no_results)) {
        hstr_last_error.m_set("HLDAE846E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_attrlist) failed with error ");
        hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 3;
    }

    int inl_ret = m_convert_to_vector(adsc_co_ldap.adsc_attr_desc, adsl_v_attributes);
    if (inl_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAE175E: m_convert_to_vector() failed with error %d.", inl_ret);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 4;
    }
    bool bo_log_details = true;
    if (bo_log_details) {
        ds_hstring hstr_log(ads_wsp_helper, 2000);
        hstr_log.m_write("HLDAD233D: m_get_attr_list() returns ");
        if (adsl_v_attributes->m_size() > 0) {
            for (HVECTOR_FOREACH(ds_attribute_string, adsl_cur, *adsl_v_attributes)) {
                const ds_attribute_string& dsl_attr = HVECTOR_GET(adsl_cur);
                const ds_hstring& rdsl_dn = dsl_attr.m_get_dn();
                const ds_hstring& rdsl_name = dsl_attr.m_get_name();
                hstr_log.m_writef(" DN: '%.*s'. Attribute name: %.*s.",
                    rdsl_dn.m_get_len(), rdsl_dn.m_get_ptr(), rdsl_name.m_get_len(), rdsl_name.m_get_ptr());
                if (bo_with_val) {
                    const ds_hvector<ds_hstring>& ds_v_vals = dsl_attr.m_get_values();
                    int in_val_idx = 0;
                    for ( HVECTOR_FOREACH(ds_hstring, adsl_cur2, ds_v_vals) ) {
                        const ds_hstring& rdsl_value = HVECTOR_GET(adsl_cur2);
                        hstr_log.m_writef(" Value[%d]:%.*s", in_val_idx, rdsl_value.m_get_len(), rdsl_value.m_get_ptr());
                        in_val_idx++;
                    }
                }
            }
        }
		ads_wsp_helper->m_log(ied_sdh_log_details, hstr_log.m_const_str());
    }

    return SUCCESS;
}

/**Determine, whether a user is member in a group.<br>
 * @param ahstr_user_dn [in] DN of the user, for which the membership relation shall be determined.
 * @param ahstr_group_dn[in] DN of the group, for which the membership relation shall be determined.
 * @param ain_ret[out] true, if the DN is the DN of an user.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_is_member(const ds_hstring* ahstr_user_dn, const ds_hstring* ahstr_group_dn, bool* abo_ret) {
    if ((ahstr_user_dn == NULL) || (ahstr_group_dn == NULL)) {
        hstr_last_error.m_set("HLDAE376E: Invalid parameter to m_is_member.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
	}
    return m_is_member(ahstr_user_dn->m_get_ptr(), ahstr_user_dn->m_get_len(), 
		               ahstr_group_dn->m_get_ptr(), ahstr_group_dn->m_get_len(), abo_ret);
}

/**
 * This interface uses char-pointer and length-info instead of ds_hstring. See the ds_hstring-API for a detailed description. 
 * @author: Joachim Frank
*/
int ds_ldap::m_is_member(const char* ach_user_dn, int in_len_user_dn, const char* ach_group_dn, int in_len_group_dn, bool* abo_ret) {
	
	if(abo_ret != NULL) {
		*abo_ret = false; // Reset return value.
	}

    if ( (ach_user_dn == NULL)  || (in_len_user_dn <= 0) 
    ||   (ach_group_dn == NULL) || (in_len_group_dn <= 0)
    ||   (abo_ret == NULL)                                              ) {
        hstr_last_error.m_set("HLDAE376E: Invalid parameter to m_is_member.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD011D: m_is_member() for DN '%.*s' and group '%.*s'.", in_len_user_dn, ach_user_dn
                                                                                                          , in_len_group_dn,  ach_group_dn);

    //*abo_ret = false; // Reset return value.

    ds_hvector<ds_hstring> dsl_v_dns(ads_wsp_helper);
    ds_hstring hstr_group_dn(ads_wsp_helper, ach_group_dn, in_len_group_dn);
    int inl_ret = m_get_members(&dsl_v_dns, &hstr_group_dn); // Get the users, which are member in the group hstr_group_dn.
    if (inl_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAE375E: m_get_membership() failed with error %d for %s", inl_ret, hstr_group_dn.m_get_ptr());
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, dsl_v_dns)) {
        const ds_hstring& hstr_dn = HVECTOR_GET(adsl_cur);
        // Get the DN and compare with the delivered one.
        if (hstr_dn.m_equals_ic(ach_user_dn, in_len_user_dn)) {
            *abo_ret = true;
            ads_wsp_helper->m_log(ied_sdh_log_details, "HLDAD012D: m_is_member(): true.");
            return SUCCESS;
        }
    }

    ads_wsp_helper->m_log(ied_sdh_log_details, "HLDAD013D: m_is_member(): false.");
    return SUCCESS;
}


/**Determine the parent's DN for an item.
 * @param ahstr_dn_item [in] DN of the item, for which the parent shall be determined.
 * @param ahstr_parent_dn[out] DN of the parent.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_get_parent(const ds_hstring* ahstr_dn_item, ds_hstring* ahstr_parent_dn) {
    if ( (ahstr_dn_item == NULL)   || (ahstr_dn_item->m_get_len() < 1)
    ||   (ahstr_parent_dn == NULL)                                      ) {
        hstr_last_error.m_set("HLDAE624E: Invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD014D: m_get_parent() for DN '%s'.", ahstr_dn_item->m_get_ptr());

    // Check existance of ahstr_dn_item.
    ds_hstring hstr_dn_item_resolved(ads_wsp_helper, "");
    int inl_ret = m_lookup(ahstr_dn_item, &hstr_dn_item_resolved);
    if (inl_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAE623E: m_lookup() failed with error %d.", inl_ret);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    // be careful if hstr_dn_item is the root element!
    if (hstr_dn_item_resolved.m_equals_ic(hstrg_base)) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAE587E: Item is the root element, which has no parent: %s.", hstr_dn_item_resolved.m_get_ptr());
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 3;
    }

    // VERY SIMPLE; MUST BE IMPROVED; J.Lauenstein will provide a method.
    // Find first not escaped comma -> this is the first DN-separator. All behind this is the parent DN.
    int in_pos_backslash = ahstr_dn_item->m_find_first_of(",");
    if (in_pos_backslash == -1) { // Error; at least one comma must be included.
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAE586E: DN does not contain a ',': %s.", hstr_dn_item_resolved.m_get_ptr());
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 4;
    }

    // Get the tree items for the DN
    ds_hvector<ds_hstring> dsl_v_tree_dns(ads_wsp_helper);
    inl_ret = m_get_tree_dns(&hstr_dn_item_resolved, &dsl_v_tree_dns, false, true);
    if (inl_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HEALDE585E: m_get_tree_dns() failed with error %d.", inl_ret);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 5;
    }
    int in_count = (int)dsl_v_tree_dns.m_size();
    if (in_count <= 1) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HEALDE507E: Count of tree items is too less %d.", in_count);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 6;
    }

    // Index 1 holds the parent
    ahstr_parent_dn->m_set(dsl_v_tree_dns.m_get_first_element()->ads_next->dsc_element);
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD015D: Parent resolved to '%s'.", ahstr_parent_dn->m_get_ptr());

    return SUCCESS;
}


/**Determine, whether an item resides in a tree.<br>
 * @param ahstr_dn_item [in] DN of the item, for which the location shall be determined.
 * @param ahstr_tree_dn[in] DN of the tree.
 * @param abo_is_in_tree[out] true, if ahstr_dn_item resides in ahstr_tree_dn.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_is_item_in_tree(const ds_hstring* ahstr_dn_item, const ds_hstring* ahstr_tree_dn, bool* abo_is_in_tree) {
    const char* ach_dn_item = NULL;
    int in_len_dn_item = 0;
    if (ahstr_dn_item != NULL) {
        ach_dn_item    = ahstr_dn_item->m_get_ptr();
        in_len_dn_item = ahstr_dn_item->m_get_len();
    }
    const char* ach_tree_dn = NULL;
    int in_len_tree_dn = 0;
    if (ahstr_tree_dn != NULL) {
        ach_tree_dn    = ahstr_tree_dn->m_get_ptr();
        in_len_tree_dn = ahstr_tree_dn->m_get_len();
    }
    return m_is_item_in_tree(ach_dn_item, in_len_dn_item, ach_tree_dn, in_len_tree_dn, abo_is_in_tree);
}

/**
 * This interface uses char-pointer and length-info instead of ds_hstring. See the ds_hstring-API for a detailed description. 
 * @author: Joachim Frank
*/
int ds_ldap::m_is_item_in_tree(const char* ach_dn_item, int in_len_dn_item, const char* ach_tree_dn, int in_len_tree_dn, bool* abo_is_in_tree) {
    if ( (ach_dn_item == NULL) || (in_len_dn_item < 1)
    ||   (ach_tree_dn == NULL) || (in_len_tree_dn < 1)
    ||   (abo_is_in_tree == NULL)                                        ) {
        hstr_last_error.m_set("HLDAE634E: Invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD017D: m_is_item_in_tree() for DN '%.*s' and tree-DN '%.*s'.",
                                    in_len_dn_item, ach_dn_item, in_len_tree_dn, ach_tree_dn);

    // Check existance of hstr_dn_item.
    ds_hstring hstr_dn_item_resolved(ads_wsp_helper, "");
    ds_hstring hstr_dn_item(ads_wsp_helper, ach_dn_item, in_len_dn_item);
    int inl_ret = m_lookup(&hstr_dn_item, &hstr_dn_item_resolved);
    if (inl_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAE633E: m_lookup() failed with error %d for %s.", inl_ret, hstr_dn_item.m_get_ptr());
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    // Check existance of hstr_dn_tree
    ds_hstring hstr_dn_tree_resolved(ads_wsp_helper, "");
    ds_hstring hstr_tree_dn(ads_wsp_helper, ach_tree_dn, in_len_tree_dn);
    inl_ret = m_lookup(&hstr_tree_dn, &hstr_dn_tree_resolved);
    if (inl_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAE632E: m_lookup() failed with error %d for %s.", inl_ret, hstr_tree_dn.m_get_ptr());
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 3;
    }

    // VERY SIMPLE; MUST BE IMPROVED; J.Lauenstein will provide a method.
    // Find occurence of the hstr_dn_tree_resolved inside the hstr_dn_item_resolved.
    if (hstr_dn_item_resolved.m_search_ic(hstr_dn_tree_resolved) >= 0) {
        // hstr_dn_tree_resolved is a part of hstr_dn_item_resolved.
        *abo_is_in_tree = true;
    }

    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD018D: is in tree: %d.", (*abo_is_in_tree));
    return SUCCESS;
}


/**Determine, whether a DN is a user.<br>
 * Criteria: If the object class 'person' is found -> this is a user.
 * @param ahstr_dn [in] DN, which shall be investigated.
 * @param abo_is_user[out] true, if the DN is a user.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_is_user(const ds_hstring* ahstr_dn, bool* abo_is_user) {
    if ( (ahstr_dn == NULL) || (ahstr_dn->m_get_len() < 1)
    ||   (abo_is_user == NULL) ) {
        hstr_last_error.m_set("HLDAE597E: Invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD028D: m_is_user() for '%s'.", ahstr_dn->m_get_ptr());

    ds_hvector<ds_attribute_string> dsl_v_objectclass(ads_wsp_helper);
    ds_hstring hstr_attrlist(ads_wsp_helper, "objectClass");
    ds_hstring hstr_filter(ads_wsp_helper, "(objectClass=person)");
    int inl_ret = m_read_attributes(&hstr_attrlist, &hstr_filter, ahstr_dn, ied_sear_baseobject, &dsl_v_objectclass);
    if (inl_ret != SUCCESS) {
        ds_hstring hstr_msg(ads_wsp_helper, "HLDAPE600E: m_is_user failed, because m_read_attributes failed with error");
        hstr_msg.m_writef(" %d. Details: %.*s", inl_ret, hstr_last_error.m_get_len(), hstr_last_error.m_get_ptr());
        hstr_last_error.m_set(hstr_msg);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    // Loop over the returned values and look for 'person'
    for (HVECTOR_FOREACH(ds_attribute_string, adsl_cur, dsl_v_objectclass)) {
        const ds_attribute_string& dsl_attr = HVECTOR_GET(adsl_cur);
        const ds_hvector<ds_hstring>& dsl_val = dsl_attr.m_get_values();
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur2, dsl_val)) {
            const ds_hstring& hstr_val = HVECTOR_GET(adsl_cur2);
            if (hstr_val.m_equals_ic("person")) {
                // Object class 'person' found -> this is a user.
                *abo_is_user = true;
                ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD020D: '%s' is a user.", ahstr_dn->m_get_ptr());
                return SUCCESS;
            }
        }
    }

    // Object class 'person' not found -> this is not a user.
    *abo_is_user = false;

    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD019D: '%s' is not a user.", ahstr_dn->m_get_ptr());
    return SUCCESS;
}

/**Resolve group memberships in UP direction:<br>
 * 1) Those groups, where an item (defined by its DN) is member in. If ahstr_dn is null, the group membership of the logged user are determined.
 * @param adsl_v_dn [out] Vector, which contains the DNs, where the item is member in OR the DNs, which are member of the specified group.
 * @param ahstr_dn[in] DN of the item, for which the according membership relations shall be searched. If NULL, the search is done for the last resolved DN.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_get_membership(ds_hvector<ds_hstring>* adsl_v_dn, const ds_hstring* ahstr_dn, bool bop_nested) {
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD029D: m_get_membership() for '%s';", 
        (ahstr_dn==NULL?"<null>":ahstr_dn->m_get_ptr()));

    if ( (ahstr_dn == NULL) || (ahstr_dn->m_get_len() <= 0) ) {
        // Determine the groups, where the logged user is a member of.
        adsc_co_ldap.ac_dn = NULL;
        adsc_co_ldap.imc_len_dn = 0;
    }
    else { // Determine membership relations (groups) for a special DN
        adsc_co_ldap.ac_dn = const_cast<char*>(ahstr_dn->m_get_ptr());
        adsc_co_ldap.imc_len_dn = ahstr_dn->m_get_len();
    }
	adsc_co_ldap.iec_chs_dn = ied_chs_utf_8;
	adsc_co_ldap.iec_co_ldap = (bop_nested)? ied_co_ldap_get_membership_nested : ied_co_ldap_get_membership;
    
    adsc_co_ldap.iec_sear_scope = ied_sear_basedn; // We search the groups in a specified folder (in some LDAPs the member-relation is only stored at the groups)!
                                                   // The name 'ied_sear_basedn' is miss-leading: it really means the folder, where the search shall be done (not the LDAP-base!).
                                                   // The entry in wsp.xml is '<base-dn>' (miss-leading!!).

    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if (bo_ret == false) {
        hstr_last_error.m_set("HLDAE875E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_membership) failed: method returned false");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    if ((adsc_co_ldap.iec_ldap_resp != ied_ldap_success) && (adsc_co_ldap.iec_ldap_resp != ied_ldap_no_results)) {
        hstr_last_error.m_set("HLDAE876E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_membership) failed with error ");
        hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    if (adsc_co_ldap.iec_ldap_resp == ied_ldap_no_results) { // no results were found -> this is not an error
        ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD027D: No memberships detected for '%s'.", (ahstr_dn==NULL?"<null>":ahstr_dn->m_get_ptr()));
        return SUCCESS;
    }

    // The delivered data are organized as follows:
    // adsc_co_ldap.adsc_memship_desc is the start point of a chain of dsd_ldap_val, which hold dn,length of dn, charset and a next-pointer.
    dsd_ldap_val* adsd_ldap_val_curr = adsc_co_ldap.adsc_memship_desc;

    while (adsd_ldap_val_curr) { // fill return vector
        // up to now we support only charset UTF8 in the LDAP-response
        if (adsd_ldap_val_curr->iec_chs_val != ied_chs_utf_8) {
            hstr_last_error.m_set("HLDAE711E: LDAP response is not in UTF8.");
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 3;
        }

        ds_hstring hstr_dn(ads_wsp_helper, adsd_ldap_val_curr->ac_val, adsd_ldap_val_curr->imc_len_val);
        adsl_v_dn->m_add(hstr_dn);
        ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD026D: '%s' has membership relation to '%s'.", (ahstr_dn==NULL?"<null>":ahstr_dn->m_get_ptr()), hstr_dn.m_get_ptr());

        adsd_ldap_val_curr = adsd_ldap_val_curr->adsc_next_val;
    } // while (adsd_ldap_val_curr)

    return SUCCESS;
}
/**Resolve group memberships in DOWN direction:<br>
 * Those users and groups, which are member in the group specified by the DN.
 * @param adsl_v_dn [out] Vector, which contains the DNs, where the item is member in OR the DNs, which are member of the specified group.
 * @param ahstr_dn[in] DN of the item, for which the according membership relations shall be searched. If NULL, the search is done for the last resolved DN.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_get_members(ds_hvector<ds_hstring>* adsl_v_dn, const ds_hstring* ahstr_dn) {
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD029D: m_get_membership() for '%s';", 
        (ahstr_dn==NULL?"<null>":ahstr_dn->m_get_ptr()));

    if ( (ahstr_dn == NULL) || (ahstr_dn->m_get_len() <= 0) ) {
		return 4;
    }
    // Determine membership relation (groups OR users) for a special DN
    adsc_co_ldap.ac_dn = const_cast<char*>(ahstr_dn->m_get_ptr());
    adsc_co_ldap.imc_len_dn = ahstr_dn->m_get_len();
    adsc_co_ldap.iec_co_ldap = ied_co_ldap_get_members;
    
    adsc_co_ldap.iec_sear_scope = ied_sear_basedn; // We search the groups in a specified folder (in some LDAPs the member-relation is only stored at the groups)!
                                                   // The name 'ied_sear_basedn' is miss-leading: it really means the folder, where the search shall be done (not the LDAP-base!).
                                                   // The entry in wsp.xml is '<base-dn>' (miss-leading!!).

    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if (bo_ret == false) {
        hstr_last_error.m_set("HLDAE875E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_membership) failed: method returned false");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    if ((adsc_co_ldap.iec_ldap_resp != ied_ldap_success) && (adsc_co_ldap.iec_ldap_resp != ied_ldap_no_results)) {
        hstr_last_error.m_set("HLDAE876E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_get_membership) failed with error ");
        hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    if (adsc_co_ldap.iec_ldap_resp == ied_ldap_no_results) { // no results were found -> this is not an error
        ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD027D: No memberships detected for '%s'.", (ahstr_dn==NULL?"<null>":ahstr_dn->m_get_ptr()));
        return SUCCESS;
    }

    // The delivered data are organized as follows:
    // adsc_co_ldap.adsc_memship_desc is the start point of a chain of dsd_ldap_val, which hold dn,length of dn, charset and a next-pointer.
    dsd_ldap_val* adsd_ldap_val_curr = adsc_co_ldap.adsc_memship_desc;

    while (adsd_ldap_val_curr) { // fill return vector
        // up to now we support only charset UTF8 in the LDAP-response
        if (adsd_ldap_val_curr->iec_chs_val != ied_chs_utf_8) {
            hstr_last_error.m_set("HLDAE711E: LDAP response is not in UTF8.");
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 3;
        }

        ds_hstring hstr_dn(ads_wsp_helper, adsd_ldap_val_curr->ac_val, adsd_ldap_val_curr->imc_len_val);
        adsl_v_dn->m_add(hstr_dn);
        ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD026D: '%s' has membership relation to '%s'.", (ahstr_dn==NULL?"<null>":ahstr_dn->m_get_ptr()), hstr_dn.m_get_ptr());

        adsd_ldap_val_curr = adsd_ldap_val_curr->adsc_next_val;
    } // while (adsd_ldap_val_curr)

    return SUCCESS;
}

/**Collect all instances of an attribute concerning inheritage.<br>
 * The specified attribute will be fetched 
 *    a) from the item itself, 
 *    b) from the groups, where the item is member in,
 *    c) from all tree items.
 * @param ahstr_dn [in] DN of the item.
 * @param ahstr_attrname [in] Name of the attribute.
 * @param adsl_attrstr_own [out] This structure will get filled with the attribute of the item itself.
 * @param adsl_v_attr_groups [out] Vector, which contains the attributes, which were inherited from groups.
 * @param adsl_v_attr_tree [out] Vector, which contains the attributes, which were inherited from tree.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_collect_attributes(const ds_hstring* ahstr_dn, const ds_hstring* ahstr_attrname, ds_attribute_string* adsl_attrstr_own,
                                  ds_hvector<ds_attribute_string>* adsl_v_attr_groups,
                                  ds_hvector<ds_attribute_string>* adsl_v_attr_tree) {
    const char* ach_attrname_zt = NULL;
    if (ahstr_attrname != NULL) {
        ach_attrname_zt = ahstr_attrname->m_get_ptr();
    }
    return m_collect_attributes(ahstr_dn, ach_attrname_zt, adsl_attrstr_own, adsl_v_attr_groups, adsl_v_attr_tree);
}

/**Collect all instances of an attribute concerning inheritage.<br>
 * The specified attribute will be fetched 
 *    a) from the item itself, 
 *    b) from the groups, where the item is member in,
 *    c) from all tree items.
 * @param ahstr_dn [in] DN of the item.
 * @param ach_attrname_zt [in] Name of the attribute (zero-terminated!).
 * @param adsl_attrstr_own [out] This structure will get filled with the attribute of the item itself.
 * @param adsl_v_attr_groups [out] Vector, which contains the attributes, which were inherited from groups.
 * @param adsl_v_attr_tree [out] Vector, which contains the attributes, which were inherited from tree.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_collect_attributes(const ds_hstring* ahstr_dn, const char* ach_attrname_zt, ds_attribute_string* adsl_attrstr_own,
    ds_hvector<ds_attribute_string>* adsl_v_attr_groups, ds_hvector<ds_attribute_string>* adsl_v_attr_tree) {
    if ( (ahstr_dn == NULL) || (ahstr_dn->m_get_len() == 0) 
    ||   (ach_attrname_zt == NULL)
    ||   (adsl_attrstr_own == NULL) || (adsl_v_attr_groups == NULL) || (adsl_v_attr_tree == NULL) ) {
        hstr_last_error.m_set("HLDAPE563E: Invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD025D: m_collect_attributes() for '%s'. Attribute name: %s.", ahstr_dn->m_get_ptr(), ach_attrname_zt);

    //---------------------------------------------
    // 1) Read the requested attribute from the item itself (OWN).
    //---------------------------------------------
    ds_hstring hstr_filter(ads_wsp_helper, "");
    ds_hvector<ds_attribute_string> dsl_v_attr_own(ads_wsp_helper);
    int inl_ret = m_read_attributes(ach_attrname_zt, &hstr_filter, ahstr_dn,
                                                ied_sear_baseobject, &dsl_v_attr_own);
    if (inl_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAPE483E: m_collect_attributes() failed with error %d.", inl_ret);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return inl_ret+100;
    }

    // Copy the OWN values into the delivered structure for OWN
    adsl_attrstr_own->m_set_dn(ahstr_dn);
    adsl_attrstr_own->m_set_name(ach_attrname_zt, strlen(ach_attrname_zt));
    int in_count = (int)dsl_v_attr_own.m_size();
    if (in_count == 0) {
        // No attribute found for OWN -> nothing to do.
        ads_wsp_helper->m_log(ied_sdh_log_details, "HLDAD024D: No OWN attribute found.");
    }
    else if (in_count == 1) {
        const ds_hvector<ds_hstring>& dsl_values = dsl_v_attr_own.m_get_first().m_get_values();
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur, dsl_values)) {
            const ds_hstring& hstr_val = HVECTOR_GET(adsl_cur);
            adsl_attrstr_own->m_add_to_values(&hstr_val);
            ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD023D: OWN attribute: %s.", hstr_val.m_get_ptr());
        }
    }
    else { // error
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAPE573E: Invalid count of attributes: %d.", in_count);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }


    //---------------------------------------------
    // 2) Read the requested attribute from groups, if DN is a user.
    //---------------------------------------------
    bool bo_dn_is_user = false;
    inl_ret = m_is_user(ahstr_dn, &bo_dn_is_user);
    if (inl_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAPE583E: m_is_user() failed with error %d.", inl_ret);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return inl_ret+200;
    }
    if (bo_dn_is_user) { // We search in groups only, when item is a user. Later: Nested groups ??
        ds_hvector<ds_hstring> dsl_v_dns(ads_wsp_helper);
        inl_ret = m_get_membership(&dsl_v_dns, ahstr_dn, true); // Get the groups, where the item ahstr_dn is member in.
        if (inl_ret != SUCCESS) {
            hstr_last_error.m_reset();
            hstr_last_error.m_writef("HLDAPE584E: m_get_membership() failed with error %d.", inl_ret);
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return inl_ret+300;
        }
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur, dsl_v_dns)) {
            const ds_hstring& hstr_group_dn = HVECTOR_GET(adsl_cur);
            ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD022D: Look for attribute '%s' in group '%s'.", ach_attrname_zt, hstr_group_dn.m_get_ptr());
            inl_ret = m_read_attributes(ach_attrname_zt, &hstr_filter, &hstr_group_dn, ied_sear_baseobject, adsl_v_attr_groups);
            if (inl_ret != SUCCESS) {
                hstr_last_error.m_reset();
                hstr_last_error.m_writef("HLDAPE585E: m_read_attributes() failed with error %d.", inl_ret);
                ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
                return inl_ret+400;
            }
        }
    }

    //---------------------------------------------
    // 3) Read the requested attribute from items of the DN's tree.
    //---------------------------------------------
    // Get the tree items for the DN.
    ds_hvector<ds_hstring> dsl_v_tree_dns(ads_wsp_helper);
    inl_ret = m_get_tree_dns(ahstr_dn, &dsl_v_tree_dns, false, true);
    if (inl_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAPE586E: m_get_tree_dns() failed with error %d.", inl_ret);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return inl_ret+500;
    }
    // Start at index 1, because at 0 is our DN, which was already investigated.
    const dsd_hvec_elem<ds_hstring>* adsl_cur = dsl_v_tree_dns.m_get_first_element();
    if(adsl_cur == NULL)
        return SUCCESS;
    adsl_cur = adsl_cur->ads_next;
    for ( ; adsl_cur != NULL; adsl_cur=adsl_cur->ads_next ) {
        const ds_hstring& hstr_tree_dn = adsl_cur->dsc_element;
        ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD021D: Look for attribute '%s' in tree '%s'.", ach_attrname_zt, hstr_tree_dn.m_get_ptr());
        inl_ret = m_read_attributes(ach_attrname_zt, &hstr_filter, &hstr_tree_dn, ied_sear_baseobject, adsl_v_attr_tree);
        if (inl_ret != SUCCESS) {
            hstr_last_error.m_reset();
            hstr_last_error.m_writef("HLDAPE587E: m_read_attributes() failed with error %d.", inl_ret);
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return inl_ret+600;
        }
    }

    return SUCCESS;
}



/**Read one ore more attributes from a DN.<br>
 * @param ahstr_attr_list [in] Comma seperated list of attribute names. May be NULL, then all attributes will be fetched.
 * @param ahstr_filter [in] The filter to get set. May be NULL.
 * @param ahstr_dn [in] DN of the item, where to search or where to start search (depends on the search scope). If NULL or empty, the current logged user's DN is used.
 * @param iec_search_scope [in] The search scope to be used (e.g. ied_sear_onelevel).
 * @param adsl_v_attributes [out] Vector, which contains the read attributes. These attributes may come from different DNs (depends on the search scope)!
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_read_attributes(const ds_hstring* ahstr_attr_list, const ds_hstring* ahstr_filter, const ds_hstring* ahstr_dn, ied_scope_ldap_def iec_search_scope,
                                       ds_hvector<ds_attribute_string>* adsl_v_attributes) {
    const char* ach_attr_list_zt = NULL;
    if (ahstr_attr_list != NULL) {
        ach_attr_list_zt = ahstr_attr_list->m_get_ptr();
    }
    return m_read_attributes(ach_attr_list_zt, ahstr_filter, ahstr_dn, iec_search_scope, adsl_v_attributes);
}

/**Read one ore more attributes from a DN.<br>
 * @param ach_attr_list_zt [in] Comma seperated (zero-terminated!) list of attribute names. May be NULL, then all attributes will be fetched.
 * @param ahstr_filter [in] The filter to get set. May be NULL.
 * @param ahstr_dn [in] DN of the item, where to search or where to start search (depends on the search scope). If NULL or empty, the current logged user's DN is used.
 * @param iec_search_scope [in] The search scope to be used (e.g. ied_sear_onelevel).
 * @param adsl_v_attributes [out] Vector, which contains the read attributes. These attributes may come from different DNs (depends on the search scope)!
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_read_attributes(const char* ach_attr_list_zt, const ds_hstring* ahstr_filter, const ds_hstring* ahstr_dn, ied_scope_ldap_def iec_search_scope,
        ds_hvector<ds_attribute_string>* adsl_v_attributes) {
    if (adsl_v_attributes == NULL) { // no vector was passed -> we are done
        hstr_last_error.m_set("HLDAPE635E: m_read_attributes() failed: No returning vector passed.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD030D: m_read_attributes() with scope '%d'. DN: '%s'. Attribute list: %s. Filter: '%s'.", (int)iec_search_scope,
        (ahstr_dn==NULL?"<null>":ahstr_dn->m_get_ptr()), 
        (ach_attr_list_zt==NULL?"<null>":ach_attr_list_zt),
        (ahstr_filter==NULL?"<null>":ahstr_filter->m_get_ptr())  );

    adsc_co_ldap.iec_co_ldap      = ied_co_ldap_search;
    adsc_co_ldap.iec_sear_scope   = iec_search_scope;
    // attribute list
    if ( (ach_attr_list_zt == NULL) || (strlen(ach_attr_list_zt) == 0) ) { // empty list -> get all attributes
        adsc_co_ldap.ac_attrlist        = NULL;
        adsc_co_ldap.imc_len_attrlist   = 0;
    }
    else {
        adsc_co_ldap.ac_attrlist        = const_cast<char*>(ach_attr_list_zt);
        adsc_co_ldap.imc_len_attrlist   = strlen(ach_attr_list_zt);
    }
    adsc_co_ldap.iec_chs_attrlist   = ied_chs_utf_8;
    // filter
    if ( (ahstr_filter != NULL) && (ahstr_filter->m_get_len() > 0) ) {
        adsc_co_ldap.ac_filter        = const_cast<char*>(ahstr_filter->m_get_ptr());
        adsc_co_ldap.imc_len_filter   = ahstr_filter->m_get_len();
    }
    else {
        adsc_co_ldap.ac_filter        = NULL;
        adsc_co_ldap.imc_len_filter   = 0;
    }
    adsc_co_ldap.iec_chs_filter   = ied_chs_utf_8;
    // DN, where to start search; if empty -> the logged user's DN is meant
    if ( (ahstr_dn != NULL) && (ahstr_dn->m_get_len() > 0) ) {
        adsc_co_ldap.ac_dn        = const_cast<char*>(ahstr_dn->m_get_ptr());
        adsc_co_ldap.imc_len_dn   = ahstr_dn->m_get_len();
    }
    else {
        adsc_co_ldap.ac_dn        = NULL;
        adsc_co_ldap.imc_len_dn   = 0;
    }
    adsc_co_ldap.iec_chs_dn   = ied_chs_utf_8;
    
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if (bo_ret == false) {
        hstr_last_error.m_writef("HLDAPE525E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_search) failed: method returned false. Attributes: %s. Filter: %s.",
            (ach_attr_list_zt==NULL?"<null>":ach_attr_list_zt), ahstr_filter->m_get_ptr());
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    if (adsc_co_ldap.iec_ldap_resp == ied_ldap_no_results) { // no results were found -> this is not an error although ied_ldap_success is not set
        ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD032D: No attributes found. DN: '%s'. Attribute list: %s. Filter: '%s'.",
        (ahstr_dn==NULL?"<null>":ahstr_dn->m_get_ptr()), 
        (ach_attr_list_zt==NULL?"<null>":ach_attr_list_zt),
        (ahstr_filter==NULL?"<null>":ahstr_filter->m_get_ptr())  );
        return SUCCESS;
    }

    if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
        hstr_last_error.m_writef("HLDAPE524E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_search) failed with error %d. Attributes: %s. Filter: %s.",
            adsc_co_ldap.iec_ldap_resp, (ach_attr_list_zt==NULL?"<null>":ach_attr_list_zt), (ahstr_filter==NULL?"<null>":ahstr_filter->m_get_ptr()));
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 3;
    }

    if (adsc_co_ldap.adsc_attr_desc == NULL) { // nothing found -> it is an error, because ied_ldap_no_results was not set ! 
        hstr_last_error.m_writef("HLDAPE523E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_search) failed: adsc_co_ldap.adsc_attr_desc == NULL. Attributes: %s. Filter: %s.",
            (ach_attr_list_zt==NULL?"<null>":ach_attr_list_zt), ahstr_filter->m_get_ptr());
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 4;
    }

    int in_ret = m_convert_to_vector(adsc_co_ldap.adsc_attr_desc, adsl_v_attributes);
    if (in_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("HLDAE255E: m_convert_to_vector() failed with error %d.", in_ret);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 5;
    }

    bool bo_log_details = true;
    if (bo_log_details) {
        ds_hstring hstr_log(ads_wsp_helper, 2000);
        hstr_log.m_write("HLDAD033D: m_read_attributes() returns ");
        if (adsl_v_attributes->m_size() > 0) {
            for (HVECTOR_FOREACH(ds_attribute_string, adsl_cur, *adsl_v_attributes)) {
                const ds_attribute_string& dsl_attr = HVECTOR_GET(adsl_cur);

                hstr_log.m_writef(" DN: '%s'. Attribute name: %s.", dsl_attr.m_get_dn().m_get_ptr(), dsl_attr.m_get_name().m_get_ptr());
                int in_val_idx = 0;
                for (HVECTOR_FOREACH(ds_hstring, adsl_cur2, dsl_attr.m_get_values())) {
                    hstr_log.m_writef(" Value[%d]:%s", in_val_idx, HVECTOR_GET(adsl_cur2).m_get_ptr());
                    in_val_idx++;
                }
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_details, hstr_log.m_const_str());
    }

    return in_ret;
}


/**Check existance of a DN.<br>
 * @param ahstr_dn [in] DN of the item.
 * @param ahstr_dn_resolved [out] will be filled with the DN in correct format (no superfluous blanks, etc).
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_lookup(const ds_hstring* ahstr_dn, ds_hstring* ahstr_dn_resolved) {
    if ( (ahstr_dn == NULL) || (ahstr_dn->m_get_len() < 1) || (ahstr_dn_resolved == NULL)) {
        hstr_last_error.m_set("HLDAPE642E: Invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD040D: m_lookup() DN: '%s'.", ahstr_dn->m_get_ptr());

    adsc_co_ldap.iec_co_ldap  = ied_co_ldap_lookup;
    // DN to lookup
    adsc_co_ldap.ac_dn        = const_cast<char*>(ahstr_dn->m_get_ptr());
    adsc_co_ldap.imc_len_dn   = ahstr_dn->m_get_len();
    adsc_co_ldap.iec_chs_dn   = ied_chs_utf_8;

    // 01.03.10 Ticket[19284]: We must reset the attribute list.
    adsc_co_ldap.imc_len_attrlist = 0;
    
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if (bo_ret == false) {
        hstr_last_error.m_set("HLDAPE508E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_lookup) failed: method returned false");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    // Attention: If the DN could not be found, ied_ldap_lookup_err is returned. This values is returned in case of another error during lookup, too!!!

    if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
        hstr_last_error.m_set("HLDAPE509E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_lookup) failed with error ");
        hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 3;
    }

    if (adsc_co_ldap.adsc_attr_desc == NULL) { // nothing found -> it is an error, because ied_ldap_no_results was not set ! 
        hstr_last_error.m_set("HLDAPE510E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_lookup) failed: adsc_co_ldap.adsc_attr_desc == NULL");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 4;
    }

    ahstr_dn_resolved->m_set(adsc_co_ldap.adsc_attr_desc->ac_dn, adsc_co_ldap.adsc_attr_desc->imc_len_dn);
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD041D: m_lookup() resolved DN '%s' to '%s'.", ahstr_dn->m_get_ptr(), ahstr_dn_resolved->m_get_ptr());

    return SUCCESS;
}


/**Write one or more attributes to a DN.<br>
 * @param ahstr_dn [in] DN of the item.
 * @param dsl_attr_chain [in] Chain of attributes to be stored at the DN.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_write_attributes(const ds_hstring* ahstr_dn, dsd_ldap_attr dsl_attr_chain) {
    if ( (ahstr_dn == NULL) || (ahstr_dn->m_get_len() < 1) ) {
        hstr_last_error.m_set("HLDAPE661E: m_write_attributes() failed: Invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }

    if (ads_wsp_helper->m_is_logable(ied_sdh_log_details)) {
        ds_hstring hstr_log(ads_wsp_helper, 2000);
        hstr_log.m_writef("HLDAD042D: m_write_attributes() to DN '%s': ", ahstr_dn->m_get_ptr());

        dsd_ldap_attr* adsl_attr = &dsl_attr_chain;
        while (adsl_attr) {
            hstr_log.m_writef(" Attribute name: '%.*s'", adsl_attr->imc_len_attr, adsl_attr->ac_attr);

            int in_idx_val = 0;
            dsd_ldap_val* adsl_val = &adsl_attr->dsc_val;
            while (adsl_val) {
                hstr_log.m_writef(" Value[%d]: '%.*s'", in_idx_val, adsl_val->imc_len_val, adsl_val->ac_val);
                adsl_val = adsl_val->adsc_next_val;
                in_idx_val++;
            }

            adsl_attr = adsl_attr->adsc_next_attr;
        } // while (adsl_attr)

        ads_wsp_helper->m_log(ied_sdh_log_details, hstr_log.m_const_str());
    }

    // Search specified object class and insert if not yet there.
    // Attention: don't insert the object class into MSActiveDirectory or Siemens DirX.
    // As agreed with E.Galea this insertion shall remain although the
    // Insertion is not required for saving not-HOB-attributes (e.g. userCertificate).
    ds_hstring hstr_oc(ads_wsp_helper, "hoboc");
    int inl_ret = m_insert_objectclass(&hstr_oc, ahstr_dn, bog_insert_oc);
    if (inl_ret != SUCCESS) {
        hstr_last_error.m_writef("HLDAPE362E: m_insert_objectclass() for %s failed with error %d.", hstr_oc.m_get_ptr(), inl_ret);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }
    hstr_oc.m_set("hobphone");
    inl_ret = m_insert_objectclass(&hstr_oc, ahstr_dn, bog_insert_oc);
    if (inl_ret != SUCCESS) {
        hstr_last_error.m_writef("HLDAPE362E: m_insert_objectclass() for %s failed with error %d.", hstr_oc.m_get_ptr(), inl_ret);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    dsd_ldap_attr_desc dsl_attr_desc;
    memset(&dsl_attr_desc, 0, sizeof(dsd_ldap_attr_desc));
    dsl_attr_desc.ac_dn               = const_cast<char*>(ahstr_dn->m_get_ptr());
    dsl_attr_desc.imc_len_dn          = ahstr_dn->m_get_len();
    dsl_attr_desc.iec_chs_dn          = ied_chs_utf_8;
    dsl_attr_desc.adsc_attr           = &dsl_attr_chain;

    adsc_co_ldap.adsc_attr_desc   = &dsl_attr_desc;
    adsc_co_ldap.iec_co_ldap      = ied_co_ldap_modify;  // J.Lauenstein: use always ied_co_ldap_modify
    
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if (bo_ret == false) {
        hstr_last_error.m_set("HLDAPE662E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_modify) failed: method returned false");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 3;
    }

    if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
        hstr_last_error.m_set("HLDAPE663E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_modify) failed with error ");
        hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());

        if (adsc_co_ldap.iec_ldap_resp == ied_ldap_attr_or_val_exist) {
            // Give a special return code, when the value already exists.
            // E.g. ds_ea_ldap will react in certain way on this.
            return ied_ldap_attr_or_val_exist;
        }

        return 4;
    }

    return SUCCESS;
}


/**Create a new user in LDAP.<br>
 * @param ahstr_dn_to_create [in] DN of the user to create.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_create_user(ds_hstring* ahstr_dn_to_create) {
    // Get the first token of the DN. It will be used as user name.
    ds_hstring hstr_first_token(ads_wsp_helper, "");
    m_get_first_token_of_dn(ahstr_dn_to_create, &hstr_first_token);

    // The user's name is the first token without the prefix. Cut off the prefix.
    ds_hstring hstr_name(ads_wsp_helper, "");
    int inl_ret = m_cut_prefix(&hstr_first_token, &hstr_name);
    if (inl_ret != SUCCESS) {
        ads_wsp_helper->m_logf(ied_sdh_log_error, "HLDAPE557E: m_cut_prefix() failed with error %d.", inl_ret);
        return 100 + inl_ret;
    }

    // The user's uid is set to the user's name.
    ds_hstring hstr_uid(ads_wsp_helper, hstr_name);

    // We create a password on the fly.
    char ch_random[10];
    if (!ads_wsp_helper->m_cb_get_random(&ch_random[0], 10)) {
        ads_wsp_helper->m_log(ied_sdh_log_error, "HLDAPE558E: creation of random (for password) failed.");
        return 201;
    }

    ds_hstring hstr_pw(ads_wsp_helper, &ch_random[0], 10);
    return m_create_user(ahstr_dn_to_create, true, &hstr_name, &hstr_uid, &hstr_pw);
}


/**Create a new item in LDAP.<br>
 * @param ch_type           [in] Type of the item to be created (e.g. 'u' for a user).
 * @param ahstr_name        [in] Name of the item (without the LDAP prefix!). Will become the first part of the item's DN.
 * @param ahstr_context     [in] DN, where to create the item.
 * @param ahstr_uid         [in] Will become the attribute 'uid' in OpenDS or 'SAMAccountName' in ActiveDirectory.
 * @param ahstr_pw          [in] The password of the user in clear text. Must not be NULL, if an user shall be created.
 * @param ahstr_created_dn [out] DN of the created item.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_createnode(char ch_type, const ds_hstring* ahstr_name, const ds_hstring* ahstr_context,
                                        const ds_hstring* ahstr_uid, const ds_hstring* ahstr_pw,
                                        ds_hstring* ahstr_created_dn) {
    if ( (ahstr_name == NULL) || (ahstr_name->m_get_len() < 1)
    ||   (ahstr_context == NULL) || (ahstr_context->m_get_len() < 1)
    ||   (ahstr_created_dn == NULL)                                      ) {
        hstr_last_error.m_set("HLDAPE657E: m_createnode() called with invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD050D: m_createnode() Type: '%c'. Name: '%s'. Context: %s. UID: '%s'.", ch_type,
        ahstr_name->m_get_ptr(), ahstr_context->m_get_ptr(), (ahstr_uid==NULL?"<null>":ahstr_uid->m_get_ptr()) );

    // Construct the DN of the item to create (the prefix will be added later)
    ds_hstring hstr_dn_to_create(ads_wsp_helper, ahstr_name->m_get_ptr(), ahstr_name->m_get_len());
    hstr_dn_to_create.m_write(",");
    hstr_dn_to_create.m_write(ahstr_context->m_get_ptr(), ahstr_context->m_get_len());

    int in_ret = SUCCESS;
    switch (ch_type) {
        case C_USER:
            in_ret = m_create_user(&hstr_dn_to_create, false, ahstr_name, ahstr_uid, ahstr_pw);
            if (in_ret != SUCCESS) {
                return (in_ret + 100);
            }
            break;
        case C_DEPART:
        case C_CONTAINER:
            in_ret = m_create_ou(&hstr_dn_to_create, ahstr_name);
            if (in_ret != SUCCESS) {
                return (in_ret + 200);
            }
            break;
        case C_OBJECT:
            in_ret = m_create_object(&hstr_dn_to_create, ahstr_name);
            if (in_ret != SUCCESS) {
                return (in_ret + 300);
            }
            break;
        case C_GROUP:
            in_ret = m_create_group(&hstr_dn_to_create, ahstr_name);
            if (in_ret != SUCCESS) {
                return (in_ret + 400);
            }
            break;
        case C_DOMAIN:
            in_ret = m_create_domain(&hstr_dn_to_create, ahstr_name);
            if (in_ret != SUCCESS) {
                return (in_ret + 500);
            }
            break;
        default: {
            hstr_last_error.m_set("HLDAPE637E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed. Invalid item type: ");
            hstr_last_error += ch_type;
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 1000;
        }
    }

    ahstr_created_dn->m_reset();
    ahstr_created_dn->m_write(hstr_dn_to_create.m_get_ptr(), hstr_dn_to_create.m_get_len());
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD051D: Node was created: '%s'.", ahstr_created_dn->m_get_ptr());

    return in_ret;
}


/**Delte an item from LDAP.<br>
 * @param ahstr_dn [in] DN of the item to be deleted.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_deletenode(const ds_hstring* ahstr_dn) {

    if ( (ahstr_dn == NULL) || (ahstr_dn->m_get_len() < 1) ) {
        hstr_last_error.m_set("HLDAPE757E: m_deletenode() called with invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD053D: m_deletenode(): '%s'.", ahstr_dn->m_get_ptr());

    adsc_co_ldap.ac_dn            = const_cast<char*>(ahstr_dn->m_get_ptr());
    adsc_co_ldap.imc_len_dn       = ahstr_dn->m_get_len();
    adsc_co_ldap.iec_chs_dn       = ied_chs_utf_8;
    adsc_co_ldap.adsc_attr_desc   = NULL;
    adsc_co_ldap.iec_co_ldap      = ied_co_ldap_delete;
    
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if (bo_ret == false) {
        hstr_last_error.m_set("HLDAPE658E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_delete) failed: method returned false");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
        hstr_last_error.m_set("HLDAPE659E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_delete) failed with error ");
        hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 3;
    }

    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD052D: Node was deleted: '%s'.", ahstr_dn->m_get_ptr());
    return SUCCESS;
}



/**Create a user in LDAP.<br>
 * @param ahstr_dn          [in] DN to be created (with or without the LDAP prefix according to bo_dn_with_prefix).
 * @param bo_dn_with_prefix [in] Whether the DN starts with a prefix or not.
 * @param ahstr_name        [in] Name of the user (e.g. Joachim Frank). Will be written to cn. Part after the first blank will be used as surname.
 * @param ahstr_uid         [in] Will become the attribute 'uid' in OpenDS or 'SAMAccountName' in ActiveDirectory.
 * @param ahstr_pw          [in] The password of the user in clear text. Must not be NULL, if an user shall be created.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_create_user(ds_hstring* ahstr_dn, bool bo_dn_with_prefix,
                           const ds_hstring* ahstr_name, const ds_hstring* ahstr_uid, const ds_hstring* ahstr_pw) {

    bool bo_ret = false;

    if ( (ahstr_pw == NULL) || (ahstr_uid == NULL) || (ahstr_uid->m_get_len() < 1) ) { // The other parameters are already checked by the caller.
        hstr_last_error.m_set("HLDAPE333E: m_create_user() called with invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }

    // construct chain of objectclasses, and other attribute chains...
    switch (ing_ldap_srv_type) {
        case ied_sys_ldap_opends: {
            if (bo_dn_with_prefix == false) {
                ahstr_dn->m_insert_const_str(0, "cn=");
            }

            //--------------------
            // Attribute uid
            //--------------------
            dsd_ldap_val dsl_val_uid;
            memset(&dsl_val_uid, 0, sizeof(dsd_ldap_val));
            dsl_val_uid.ac_val        = const_cast<char*>(ahstr_uid->m_get_ptr());
            dsl_val_uid.imc_len_val   = ahstr_uid->m_get_len();
            dsl_val_uid.iec_chs_val   = ied_chs_utf_8;

            dsd_ldap_attr dsl_attr_uid;
            memset(&dsl_attr_uid, 0, sizeof(dsd_ldap_attr));
            dsl_attr_uid.ac_attr         = (char*)"uid";
            dsl_attr_uid.imc_len_attr    = sizeof("uid")-1;
            dsl_attr_uid.iec_chs_attr    = ied_chs_utf_8;
            dsl_attr_uid.dsc_val         = dsl_val_uid;


            //--------------------
            // Attribute sn
            //--------------------
            if ( (ahstr_name == NULL) || (ahstr_name->m_get_len() < 1) ) {
                return 3;
            }
            dsd_const_string hstr_surname(ahstr_name->m_const_str());
            int in_pos = hstr_surname.m_last_index_of(" ");
            if (in_pos != -1) {
                hstr_surname = hstr_surname.m_substring(in_pos+1);
            }
            dsd_ldap_val dsl_val_sn;
            memset(&dsl_val_sn, 0, sizeof(dsd_ldap_val));
            dsl_val_sn.ac_val        = const_cast<char*>(hstr_surname.m_get_ptr());
            dsl_val_sn.imc_len_val   = hstr_surname.m_get_len();
            dsl_val_sn.iec_chs_val   = ied_chs_utf_8;

            dsd_ldap_attr dsl_attr_sn;
            memset(&dsl_attr_sn, 0, sizeof(dsd_ldap_attr));
            dsl_attr_sn.ac_attr         = (char*)"sn";
            dsl_attr_sn.imc_len_attr    = sizeof("sn")-1;
            dsl_attr_sn.iec_chs_attr    = ied_chs_utf_8;
            dsl_attr_sn.dsc_val         = dsl_val_sn;
            dsl_attr_sn.adsc_next_attr  = &dsl_attr_uid; // put into chain


            //--------------------
            // Attribute cn
            //--------------------
            dsd_ldap_val dsl_val_cn;
            memset(&dsl_val_cn, 0, sizeof(dsd_ldap_val));
            dsl_val_cn.ac_val        = const_cast<char*>(ahstr_name->m_get_ptr());
            dsl_val_cn.imc_len_val   = ahstr_name->m_get_len();
            dsl_val_cn.iec_chs_val   = ied_chs_utf_8;

            dsd_ldap_attr dsl_attr_cn;
            memset(&dsl_attr_cn, 0, sizeof(dsd_ldap_attr));
            dsl_attr_cn.ac_attr         = (char*)"cn";
            dsl_attr_cn.imc_len_attr    = sizeof("cn")-1;
            dsl_attr_cn.iec_chs_attr    = ied_chs_utf_8;
            dsl_attr_cn.dsc_val         = dsl_val_cn;
            dsl_attr_cn.adsc_next_attr  = &dsl_attr_sn; // put into chain


            //--------------------
            // Attribute userPassword
            //--------------------
            dsd_ldap_val dsl_val_pwd;
            memset(&dsl_val_pwd, 0, sizeof(dsd_ldap_val));
            dsl_val_pwd.ac_val        = const_cast<char*>(ahstr_pw->m_get_ptr());
            dsl_val_pwd.imc_len_val   = ahstr_pw->m_get_len();
            dsl_val_pwd.iec_chs_val   = ied_chs_utf_8;

            dsd_ldap_attr dsl_attr_pwd;
            memset(&dsl_attr_pwd, 0, sizeof(dsd_ldap_attr));
            dsl_attr_pwd.ac_attr         = (char*)"userPassword";
            dsl_attr_pwd.imc_len_attr    = sizeof("userPassword")-1;
            dsl_attr_pwd.iec_chs_attr    = ied_chs_utf_8;
            dsl_attr_pwd.dsc_val         = dsl_val_pwd;
            dsl_attr_pwd.adsc_next_attr  = &dsl_attr_cn; // put into chain


            //--------------------
            // Attribute objectclass
            //--------------------
            dsd_ldap_val dsl_val_top;
            memset(&dsl_val_top, 0, sizeof(dsd_ldap_val));
            dsl_val_top.ac_val        = (char*)"top";
            dsl_val_top.imc_len_val   = sizeof("top")-1;
            dsl_val_top.iec_chs_val   = ied_chs_utf_8;

            dsd_ldap_val dsl_val_person;
            memset(&dsl_val_person, 0, sizeof(dsd_ldap_val));
            dsl_val_person.ac_val        = (char*)LDAP_PERSON;
            dsl_val_person.imc_len_val   = (int)strlen(LDAP_PERSON);
            dsl_val_person.iec_chs_val   = ied_chs_utf_8;
            dsl_val_person.adsc_next_val = &dsl_val_top;

            dsd_ldap_val dsl_val_inetorgperson;
            memset(&dsl_val_inetorgperson, 0, sizeof(dsd_ldap_val));
            dsl_val_inetorgperson.ac_val        = (char*)"inetOrgPerson";
            dsl_val_inetorgperson.imc_len_val   = sizeof("inetOrgPerson")-1;
            dsl_val_inetorgperson.iec_chs_val   = ied_chs_utf_8;
            dsl_val_inetorgperson.adsc_next_val = &dsl_val_person;

            dsd_ldap_val dsl_val_organizationalperson;
            memset(&dsl_val_organizationalperson, 0, sizeof(dsd_ldap_val));
            dsl_val_organizationalperson.ac_val        = (char*)"organizationalPerson";
            dsl_val_organizationalperson.imc_len_val   = sizeof("organizationalPerson")-1;
            dsl_val_organizationalperson.iec_chs_val   = ied_chs_utf_8;
            dsl_val_organizationalperson.adsc_next_val = &dsl_val_inetorgperson;

            dsd_ldap_attr dsl_attr_oc;
            memset(&dsl_attr_oc, 0, sizeof(dsd_ldap_attr));
            dsl_attr_oc.ac_attr         = (char*)"objectclass";
            dsl_attr_oc.imc_len_attr    = sizeof("objectclass")-1;
            dsl_attr_oc.iec_chs_attr    = ied_chs_utf_8;
            dsl_attr_oc.dsc_val         = dsl_val_organizationalperson;
            dsl_attr_oc.adsc_next_attr  = &dsl_attr_pwd;  // put into chain

            dsd_ldap_attr_desc dsl_attr_desc;
            memset(&dsl_attr_desc, 0, sizeof(dsd_ldap_attr_desc));
            dsl_attr_desc.ac_dn               = const_cast<char*>(ahstr_dn->m_get_ptr());
            dsl_attr_desc.imc_len_dn          = ahstr_dn->m_get_len();
            dsl_attr_desc.iec_chs_dn          = ied_chs_utf_8;
            dsl_attr_desc.adsc_attr           = &dsl_attr_oc;
            

            adsc_co_ldap.adsc_attr_desc   = &dsl_attr_desc;
            adsc_co_ldap.iec_co_ldap      = ied_co_ldap_add;
            
            // Do the AUX here, because the structures (e.g. dsl_val_top) are locally setup.
            bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
            break;
        }
        case ied_sys_ldap_msad: {
            if (bo_dn_with_prefix == false) {
                ahstr_dn->m_insert_const_str(0, "cn=");
            }

            //--------------------
            // Attribute sAMAccountName (passed as ahstr_uid)
            //--------------------
            dsd_ldap_val dsl_val_sam;
            memset(&dsl_val_sam, 0, sizeof(dsd_ldap_val));
            dsl_val_sam.ac_val        = const_cast<char*>(ahstr_uid->m_get_ptr());
            dsl_val_sam.imc_len_val   = ahstr_uid->m_get_len();
            dsl_val_sam.iec_chs_val   = ied_chs_utf_8;

            dsd_ldap_attr dsl_attr_sam;
            memset(&dsl_attr_sam, 0, sizeof(dsd_ldap_attr));
            dsl_attr_sam.ac_attr         = (char*)LDAP_SAMACCOUNTNAME;
            dsl_attr_sam.imc_len_attr    = sizeof(LDAP_SAMACCOUNTNAME)-1;
            dsl_attr_sam.iec_chs_attr    = ied_chs_utf_8;
            dsl_attr_sam.dsc_val         = dsl_val_sam;


            //--------------------
            // Attribute userAccountControl
            //--------------------
            int in_to_write = MS_AD_NORMAL_ACCOUNT  | MS_AD_ACCOUNTDISABLE | MS_AD_PASSWD_NOTREQD;
            ds_hstring hstr_int(ads_wsp_helper, "");
            hstr_int += in_to_write;
            dsd_ldap_val dsl_val_uac;
            memset(&dsl_val_uac, 0, sizeof(dsd_ldap_val));
            dsl_val_uac.ac_val        = const_cast<char*>(hstr_int.m_get_ptr());
            dsl_val_uac.imc_len_val   = hstr_int.m_get_len();
            dsl_val_uac.iec_chs_val   = ied_chs_utf_8;

            dsd_ldap_attr dsl_attr_uac;
            memset(&dsl_attr_uac, 0, sizeof(dsd_ldap_attr));
            dsl_attr_uac.ac_attr         = (char*)LDAP_USERACCOUNTCONTROL;
            dsl_attr_uac.imc_len_attr    = sizeof(LDAP_USERACCOUNTCONTROL)-1;
            dsl_attr_uac.iec_chs_attr    = ied_chs_utf_8;
            dsl_attr_uac.dsc_val         = dsl_val_uac;
            dsl_attr_uac.adsc_next_attr  = &dsl_attr_sam; // put into chain


            //--------------------
            // Attribute cn
            //--------------------
            dsd_ldap_val dsl_val_cn;
            memset(&dsl_val_cn, 0, sizeof(dsd_ldap_val));
            dsl_val_cn.ac_val        = const_cast<char*>(ahstr_name->m_get_ptr());
            dsl_val_cn.imc_len_val   = ahstr_name->m_get_len();
            dsl_val_cn.iec_chs_val   = ied_chs_utf_8;

            dsd_ldap_attr dsl_attr_cn;
            memset(&dsl_attr_cn, 0, sizeof(dsd_ldap_attr));
            dsl_attr_cn.ac_attr         = (char*)"cn";
            dsl_attr_cn.imc_len_attr    = sizeof("cn")-1;
            dsl_attr_cn.iec_chs_attr    = ied_chs_utf_8;
            dsl_attr_cn.dsc_val         = dsl_val_cn;
            dsl_attr_cn.adsc_next_attr  = &dsl_attr_uac; // put into chain


            //--------------------
            // Attribute objectclass
            //--------------------
            dsd_ldap_val dsl_val_top;
            memset(&dsl_val_top, 0, sizeof(dsd_ldap_val));
            dsl_val_top.ac_val        = (char*)"top";
            dsl_val_top.imc_len_val   = sizeof("top")-1;
            dsl_val_top.iec_chs_val   = ied_chs_utf_8;

            dsd_ldap_val dsl_val_person;
            memset(&dsl_val_person, 0, sizeof(dsd_ldap_val));
            dsl_val_person.ac_val        = (char*)"person";
            dsl_val_person.imc_len_val   = sizeof("person")-1;
            dsl_val_person.iec_chs_val   = ied_chs_utf_8;
            dsl_val_person.adsc_next_val = &dsl_val_top;

            dsd_ldap_val dsl_val_user;
            memset(&dsl_val_user, 0, sizeof(dsd_ldap_val));
            dsl_val_user.ac_val        = (char*)"user";
            dsl_val_user.imc_len_val   = sizeof("user")-1;
            dsl_val_user.iec_chs_val   = ied_chs_utf_8;
            dsl_val_user.adsc_next_val = &dsl_val_person;

            dsd_ldap_val dsl_val_organizationalperson;
            memset(&dsl_val_organizationalperson, 0, sizeof(dsd_ldap_val));
            dsl_val_organizationalperson.ac_val        = (char*)"organizationalPerson";
            dsl_val_organizationalperson.imc_len_val   = sizeof("organizationalPerson")-1;
            dsl_val_organizationalperson.iec_chs_val   = ied_chs_utf_8;
            dsl_val_organizationalperson.adsc_next_val = &dsl_val_user;

            dsd_ldap_attr dsl_attr_oc;
            memset(&dsl_attr_oc, 0, sizeof(dsd_ldap_attr));
            dsl_attr_oc.ac_attr         = (char*)"objectclass";
            dsl_attr_oc.imc_len_attr    = sizeof("objectclass")-1;
            dsl_attr_oc.iec_chs_attr    = ied_chs_utf_8;
            dsl_attr_oc.dsc_val         = dsl_val_organizationalperson;
            dsl_attr_oc.adsc_next_attr  = &dsl_attr_cn;  // put into chain

            dsd_ldap_attr_desc dsl_attr_desc;
            memset(&dsl_attr_desc, 0, sizeof(dsd_ldap_attr_desc));
            dsl_attr_desc.ac_dn               = const_cast<char*>(ahstr_dn->m_get_ptr());
            dsl_attr_desc.imc_len_dn          = ahstr_dn->m_get_len();
            dsl_attr_desc.iec_chs_dn          = ied_chs_utf_8;
            dsl_attr_desc.adsc_attr           = &dsl_attr_oc;
            

            adsc_co_ldap.adsc_attr_desc   = &dsl_attr_desc;
            adsc_co_ldap.iec_co_ldap      = ied_co_ldap_add;
            
            // Do the AUX here, because the structures (e.g. dsl_val_top) are locally setup.
            bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
            break;
        }
        default: {
            hstr_last_error.m_set("HLDAPE647E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed: Invalid server type.");
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 5;
        }
    }

    if (bo_ret == false) {
        hstr_last_error.m_set("HLDAPE862E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed: method returned false");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 6;
    }
    if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
        hstr_last_error.m_set("HLDAPE863E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed with error ");
        hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 7;
    }

    // ActiveDirectory: we must set the password. Hereto a SSL-connection is necessary.
    // We cannot use the functionality of ied_auth_user_pwd_change, because ied_auth_user_pwd_change will do a bind
    // with the old password. But user has no password up to now!
    if (ing_ldap_srv_type == ied_sys_ldap_msad) {
        // Set the "unicodePwd" attribute with a new value.
        // The password must be provided in UTF16 to MSAD. xsldapco1.cpp will do the conversion. We give
        // the password in UTF8 to xsldapc01.cpp.

        //--------------------
        // Attribute userAccountControl
        //--------------------
        int in_to_write = MS_AD_NORMAL_ACCOUNT  | MS_AD_DONT_EXPIRE_PASSWD;
        ds_hstring hstr_int(ads_wsp_helper, "");
        hstr_int += in_to_write;
        dsd_ldap_val dsl_val_uac;
        memset(&dsl_val_uac, 0, sizeof(dsd_ldap_val));
        dsl_val_uac.ac_val        = const_cast<char*>(hstr_int.m_get_ptr());
        dsl_val_uac.imc_len_val   = hstr_int.m_get_len();
        dsl_val_uac.iec_chs_val   = ied_chs_utf_8;

        dsd_ldap_attr dsl_attr_uac;
        memset(&dsl_attr_uac, 0, sizeof(dsd_ldap_attr));
        dsl_attr_uac.ac_attr         = (char*)LDAP_USERACCOUNTCONTROL;
        dsl_attr_uac.imc_len_attr    = sizeof(LDAP_USERACCOUNTCONTROL)-1;
        dsl_attr_uac.iec_chs_attr    = ied_chs_utf_8;
        dsl_attr_uac.dsc_val         = dsl_val_uac;


        //--------------------
        // Attribute unicodePwd
        //--------------------
        dsd_ldap_val dsl_val_pwd;
        memset(&dsl_val_pwd, 0, sizeof(dsd_ldap_val));
        dsl_val_pwd.ac_val        = const_cast<char*>(ahstr_pw->m_get_ptr());
        dsl_val_pwd.imc_len_val   = ahstr_pw->m_get_len();
        dsl_val_pwd.iec_chs_val   = ied_chs_utf_8;

        dsd_ldap_attr dsl_attr_pwd;
        memset(&dsl_attr_pwd, 0, sizeof(dsd_ldap_attr));
        dsl_attr_pwd.ac_attr         = (char*)"unicodePwd";
        dsl_attr_pwd.imc_len_attr    = (int)strlen("unicodePwd");
        dsl_attr_pwd.iec_chs_attr    = ied_chs_utf_8;
        dsl_attr_pwd.dsc_val         = dsl_val_pwd;
        dsl_attr_pwd.adsc_next_attr  = &dsl_attr_uac; // put into chain

        dsd_ldap_attr_desc dsl_attr_desc;
        memset(&dsl_attr_desc, 0, sizeof(dsd_ldap_attr_desc));
        dsl_attr_desc.ac_dn               = const_cast<char*>(ahstr_dn->m_get_ptr());
        dsl_attr_desc.imc_len_dn          = ahstr_dn->m_get_len();
        dsl_attr_desc.iec_chs_dn          = ied_chs_utf_8;
        dsl_attr_desc.adsc_attr           = &dsl_attr_pwd;
     

        int inl_ret = m_write_attributes(ahstr_dn, dsl_attr_pwd);
        if (inl_ret!= SUCCESS) {
            hstr_last_error.m_writef("HLDAPE363E: Cannot set the password for user %s.", ahstr_dn->m_get_ptr());
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 9;
        }
    }

    return SUCCESS;
}



int ds_ldap::m_create_group(ds_hstring* ahstr_dn, const ds_hstring* ahstr_name) {

    ahstr_dn->m_insert_const_str(0, "cn=");

    //--------------------
    // Attribute sAMAccountName (necessary for MS-ADS)
    //--------------------
    dsd_ldap_val dsl_val_sam;
    memset(&dsl_val_sam, 0, sizeof(dsd_ldap_val));
    dsl_val_sam.ac_val        = const_cast<char*>(ahstr_name->m_get_ptr());
    dsl_val_sam.imc_len_val   = ahstr_name->m_get_len();
    dsl_val_sam.iec_chs_val   = ied_chs_utf_8;

    dsd_ldap_attr dsl_attr_sam;
    memset(&dsl_attr_sam, 0, sizeof(dsd_ldap_attr));
    dsl_attr_sam.ac_attr         = (char*)LDAP_SAMACCOUNTNAME;
    dsl_attr_sam.imc_len_attr    = sizeof(LDAP_SAMACCOUNTNAME)-1;
    dsl_attr_sam.iec_chs_attr    = ied_chs_utf_8;
    dsl_attr_sam.dsc_val         = dsl_val_sam;

    //--------------------
    // Attribute cn
    //--------------------
    dsd_ldap_val dsl_val_cn;
    memset(&dsl_val_cn, 0, sizeof(dsd_ldap_val));
    dsl_val_cn.ac_val        = const_cast<char*>(ahstr_name->m_get_ptr());
    dsl_val_cn.imc_len_val   = ahstr_name->m_get_len();
    dsl_val_cn.iec_chs_val   = ied_chs_utf_8;

    dsd_ldap_attr dsl_attr_cn;
    memset(&dsl_attr_cn, 0, sizeof(dsd_ldap_attr));
    dsl_attr_cn.ac_attr         = (char*)"cn";
    dsl_attr_cn.imc_len_attr    = sizeof("cn")-1;
    dsl_attr_cn.iec_chs_attr    = ied_chs_utf_8;
    dsl_attr_cn.dsc_val         = dsl_val_cn;
    if (ing_ldap_srv_type == ied_sys_ldap_msad) { // put attribute sAMAccountName into the chain
        dsl_attr_cn.adsc_next_attr  = &dsl_attr_sam;
    }
    else { // OpenDS -> no attribute sAMAccountName
        dsl_attr_cn.adsc_next_attr  = NULL;
    }

    //--------------------
    // Attribute objectclass
    //--------------------
    dsd_ldap_val dsl_val_group;
    memset(&dsl_val_group, 0, sizeof(dsd_ldap_val));
    dsl_val_group.ac_val        = const_cast<char*>(hstrg_attrname_group.m_get_ptr());
    dsl_val_group.imc_len_val   = hstrg_attrname_group.m_get_len();
    dsl_val_group.iec_chs_val   = ied_chs_utf_8;

    dsd_ldap_attr dsl_attr_oc;
    memset(&dsl_attr_oc, 0, sizeof(dsd_ldap_attr));
    dsl_attr_oc.ac_attr         = (char*)"objectclass";
    dsl_attr_oc.imc_len_attr    = sizeof("objectclass")-1;
    dsl_attr_oc.iec_chs_attr    = ied_chs_utf_8;
    dsl_attr_oc.dsc_val         = dsl_val_group;
    dsl_attr_oc.adsc_next_attr  = &dsl_attr_cn;  // put into chain

    dsd_ldap_attr_desc dsl_attr_desc;
    memset(&dsl_attr_desc, 0, sizeof(dsd_ldap_attr_desc));
    dsl_attr_desc.ac_dn               = const_cast<char*>(ahstr_dn->m_get_ptr());
    dsl_attr_desc.imc_len_dn          = ahstr_dn->m_get_len();
    dsl_attr_desc.iec_chs_dn          = ied_chs_utf_8;
    dsl_attr_desc.adsc_attr           = &dsl_attr_oc;

    adsc_co_ldap.adsc_attr_desc   = &dsl_attr_desc;
    adsc_co_ldap.iec_co_ldap      = ied_co_ldap_add;
            
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if (bo_ret == false) {
        hstr_last_error.m_set("HLDAPE652E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed: method returned false");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
        hstr_last_error.m_set("HLDAPE653E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed with error ");
        hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    return SUCCESS;
}


int ds_ldap::m_create_ou(ds_hstring* ahstr_dn, const ds_hstring* ahstr_name) {
    ahstr_dn->m_insert_const_str(0, "ou=");

    //--------------------
    // Attribute ou
    //--------------------
    dsd_ldap_val dsl_val_ou;
    memset(&dsl_val_ou, 0, sizeof(dsd_ldap_val));
    dsl_val_ou.ac_val        = const_cast<char*>(ahstr_name->m_get_ptr());
    dsl_val_ou.imc_len_val   = ahstr_name->m_get_len();
    dsl_val_ou.iec_chs_val   = ied_chs_utf_8;

    dsd_ldap_attr dsl_attr_ou;
    memset(&dsl_attr_ou, 0, sizeof(dsd_ldap_attr));
    dsl_attr_ou.ac_attr      = (char*)"ou";
    dsl_attr_ou.imc_len_attr = sizeof("ou")-1;
    dsl_attr_ou.iec_chs_attr = ied_chs_utf_8;
    dsl_attr_ou.dsc_val      = dsl_val_ou;

    //--------------------
    // Attribute objectclass
    //--------------------
    dsd_ldap_val dsl_val_ounit;
    memset(&dsl_val_ounit, 0, sizeof(dsd_ldap_val));
    dsl_val_ounit.ac_val        = (char*)LDAP_OUNIT;
    dsl_val_ounit.imc_len_val   = (int)strlen(LDAP_OUNIT);
    dsl_val_ounit.iec_chs_val   = ied_chs_utf_8;

    dsd_ldap_attr dsl_attr_oc;
    memset(&dsl_attr_oc, 0, sizeof(dsd_ldap_attr));
    dsl_attr_oc.ac_attr         = (char*)"objectclass";
    dsl_attr_oc.imc_len_attr    = sizeof("objectclass")-1;
    dsl_attr_oc.iec_chs_attr    = ied_chs_utf_8;
    dsl_attr_oc.dsc_val         = dsl_val_ounit;
    dsl_attr_oc.adsc_next_attr  = &dsl_attr_ou;  // put into chain

    dsd_ldap_attr_desc dsl_attr_desc;
    memset(&dsl_attr_desc, 0, sizeof(dsd_ldap_attr_desc));
    dsl_attr_desc.ac_dn         = const_cast<char*>(ahstr_dn->m_get_ptr());
    dsl_attr_desc.imc_len_dn    = ahstr_dn->m_get_len();
    dsl_attr_desc.iec_chs_dn    = ied_chs_utf_8;
    dsl_attr_desc.adsc_attr     = &dsl_attr_oc;

    adsc_co_ldap.adsc_attr_desc = &dsl_attr_desc;
    adsc_co_ldap.iec_co_ldap    = ied_co_ldap_add;
            
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if (bo_ret == FALSE) {
        hstr_last_error.m_set("HLDAPE641E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed: method returned false");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }

    if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
        hstr_last_error.m_set("HLDAPE643E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed with error ");
        hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    return SUCCESS;
}

//inception AK
int ds_ldap::m_create_domain(ds_hstring* ahstr_dn, const ds_hstring* ahstr_name) {
    ahstr_dn->m_insert_const_str(0, "dc=");

    //--------------------
    // Attribute dc
    //--------------------
    dsd_ldap_val dsl_val_dc;
    memset(&dsl_val_dc, 0, sizeof(dsd_ldap_val));
    dsl_val_dc.ac_val        = const_cast<char*>(ahstr_name->m_get_ptr());
    dsl_val_dc.imc_len_val   = ahstr_name->m_get_len();
    dsl_val_dc.iec_chs_val   = ied_chs_utf_8;

    dsd_ldap_attr dsl_attr_dc;
    memset(&dsl_attr_dc, 0, sizeof(dsd_ldap_attr));
    dsl_attr_dc.ac_attr      = (char*)"dc";
    dsl_attr_dc.imc_len_attr = sizeof("dc")-1;
    dsl_attr_dc.iec_chs_attr = ied_chs_utf_8;
    dsl_attr_dc.dsc_val      = dsl_val_dc;

    //--------------------
    // Attribute objectclass
    //--------------------
    dsd_ldap_val dsl_val_domain;
    memset(&dsl_val_domain, 0, sizeof(dsd_ldap_val));
    dsl_val_domain.ac_val        = (char*)LDAP_DOMAIN;
    dsl_val_domain.imc_len_val   = (int)strlen(LDAP_DOMAIN);
    dsl_val_domain.iec_chs_val   = ied_chs_utf_8;

    dsd_ldap_attr dsl_attr_oc;
    memset(&dsl_attr_oc, 0, sizeof(dsd_ldap_attr));
    dsl_attr_oc.ac_attr         = (char*)"objectclass";
    dsl_attr_oc.imc_len_attr    = sizeof("objectclass")-1;
    dsl_attr_oc.iec_chs_attr    = ied_chs_utf_8;
    dsl_attr_oc.dsc_val         = dsl_val_domain;
    dsl_attr_oc.adsc_next_attr  = &dsl_attr_dc;  // put into chain

    dsd_ldap_attr_desc dsl_attr_desc;
    memset(&dsl_attr_desc, 0, sizeof(dsd_ldap_attr_desc));
    dsl_attr_desc.ac_dn         = const_cast<char*>(ahstr_dn->m_get_ptr());
    dsl_attr_desc.imc_len_dn    = ahstr_dn->m_get_len();
    dsl_attr_desc.iec_chs_dn    = ied_chs_utf_8;
    dsl_attr_desc.adsc_attr     = &dsl_attr_oc;

    adsc_co_ldap.adsc_attr_desc = &dsl_attr_desc;
    adsc_co_ldap.iec_co_ldap    = ied_co_ldap_add;
            
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if (bo_ret == FALSE) {
        hstr_last_error.m_set("HLDAPE641E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed: method returned false");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }

    if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
        hstr_last_error.m_set("HLDAPE643E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed with error ");
        hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    return SUCCESS;
}
//end AK

int ds_ldap::m_create_object(ds_hstring* ahstr_dn, const ds_hstring* ahstr_name) {
    ahstr_dn->m_insert_const_str(0, "cn=");

    //--------------------
    // Attribute cn
    //--------------------
    dsd_ldap_val dsl_val_cn;
    memset(&dsl_val_cn, 0, sizeof(dsd_ldap_val));
    dsl_val_cn.ac_val        = const_cast<char*>(ahstr_name->m_get_ptr());
    dsl_val_cn.imc_len_val   = ahstr_name->m_get_len();
    dsl_val_cn.iec_chs_val   = ied_chs_utf_8;

    dsd_ldap_attr dsl_attr_cn;
    memset(&dsl_attr_cn, 0, sizeof(dsd_ldap_attr));
    dsl_attr_cn.ac_attr         = (char*)"cn";
    dsl_attr_cn.imc_len_attr    = sizeof("cn")-1;
    dsl_attr_cn.iec_chs_attr    = ied_chs_utf_8;
    dsl_attr_cn.dsc_val         = dsl_val_cn;

    //--------------------
    // Attribute objectclass
    //--------------------
    dsd_ldap_val dsl_val_object;
    memset(&dsl_val_object, 0, sizeof(dsd_ldap_val));
    dsl_val_object.ac_val        = (char*)LDAP_HOB_GATEWAY;
    dsl_val_object.imc_len_val   = (int)strlen(LDAP_HOB_GATEWAY);
    dsl_val_object.iec_chs_val   = ied_chs_utf_8;
    dsl_val_object.adsc_next_val = NULL;

    dsd_ldap_attr dsl_attr_object;
    memset(&dsl_attr_object, 0, sizeof(dsd_ldap_attr));
    dsl_attr_object.ac_attr         = (char*)"objectclass";
    dsl_attr_object.imc_len_attr    = sizeof("objectclass")-1;
    dsl_attr_object.iec_chs_attr    = ied_chs_utf_8;
    dsl_attr_object.dsc_val         = dsl_val_object;
    dsl_attr_object.adsc_next_attr  = &dsl_attr_cn;  // put into chain

    dsd_ldap_attr_desc dsl_attr_desc;
    memset(&dsl_attr_desc, 0, sizeof(dsd_ldap_attr_desc));
    dsl_attr_desc.ac_dn               = const_cast<char*>(ahstr_dn->m_get_ptr());
    dsl_attr_desc.imc_len_dn          = ahstr_dn->m_get_len();
    dsl_attr_desc.iec_chs_dn          = ied_chs_utf_8;
    dsl_attr_desc.adsc_attr           = &dsl_attr_object;

    adsc_co_ldap.adsc_attr_desc   = &dsl_attr_desc;
    adsc_co_ldap.iec_co_ldap      = ied_co_ldap_add;
            
    bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
    if (bo_ret == false) {
        hstr_last_error.m_set("HLDAPE640E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed: method returned false");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }

    if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
        hstr_last_error.m_set("HLDAPE644E: DEF_AUX_LDAP_REQUEST (ied_co_ldap_add) failed with error ");
        hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    return SUCCESS;
}

/**Change the password of an user in LDAP.<br>
 * @param ahstr_userid [in] User name.
 * @param ahstr_pw_old [in] Old password in clear text.
 * @param ahstr_pw_new [in] New password in clear text.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_change_pwd(const ds_hstring* ahstr_userid, const ds_hstring* ahstr_pw_old, const ds_hstring* ahstr_pw_new) {
    return m_change_pwd(ahstr_userid, ahstr_pw_old, ahstr_pw_new, NULL);
}

/**Change the password of an user in LDAP.<br>
 * @param ahstr_userid [in] User name.
 * @param ahstr_pw_old [in] Old password in clear text.
 * @param ahstr_pw_new [in] New password in clear text.
 * @param ahstr_base_add [in] ahstr_base_add This will extend the LDAP's base to have something like a 'sub-base' (represents the domains). Can be NULL.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_change_pwd(const ds_hstring* ahstr_userid, const ds_hstring* ahstr_pw_old, const ds_hstring* ahstr_pw_new, const ds_hstring* ahstr_base_add) {
    const char* ach_userid = NULL;
    int in_len_userid = 0;
    if (ahstr_userid != NULL) {
        ach_userid    = ahstr_userid->m_get_ptr();
        in_len_userid = ahstr_userid->m_get_len();
    }
    const char* ach_pw_old = NULL;
    int in_len_pw_old = 0;
    if (ahstr_pw_old != NULL) {
        ach_pw_old    = ahstr_pw_old->m_get_ptr();
        in_len_pw_old = ahstr_pw_old->m_get_len();
    }
    const char* ach_pw_new = NULL;
    int in_len_pw_new = 0;
    if (ahstr_pw_new != NULL) {
        ach_pw_new    = ahstr_pw_new->m_get_ptr();
        in_len_pw_new = ahstr_pw_new->m_get_len();
    }
    const char* ach_base_add = NULL;
    int in_len_base_add = 0;
    if (ahstr_base_add != NULL) {
        ach_base_add    = ahstr_base_add->m_get_ptr();
        in_len_base_add = ahstr_base_add->m_get_len();
    }
    return m_change_pwd(ach_userid, in_len_userid, ach_pw_old, in_len_pw_old, ach_pw_new, in_len_pw_new, ach_base_add, in_len_base_add);
}

/**
 * This interface uses char-pointer and length-info instead of ds_hstring. See the ds_hstring-API for a detailed description. 
 * @author: Joachim Frank
*/
int ds_ldap::m_change_pwd(const char* ach_userid, int in_len_userid,
                          const char* ach_pw_old, int in_len_pw_old,
                          const char* ach_pw_new, int in_len_pw_new) {
    return m_change_pwd(ach_userid, in_len_userid,
                        ach_pw_old, in_len_pw_old,
                        ach_pw_new, in_len_pw_new,
                        NULL, 0);
}

/**
 * This interface uses char-pointer and length-info instead of ds_hstring. See the ds_hstring-API for a detailed description. 
 * @author: Joachim Frank
*/
int ds_ldap::m_change_pwd(const char* ach_userid, int in_len_userid,
                          const char* ach_pw_old, int in_len_pw_old,
                          const char* ach_pw_new, int in_len_pw_new,
                          const char* ach_base_add, int in_len_base_add) {
    if (!bog_sysinfo_done) { // We must read information about the LDAP server (e.g. the baseDN)
        int inl_ret = m_get_sysinfo();
        if (inl_ret < 0) { // negative: A fatal error occured. We cannot go on.
            // The error message is not yet written to log file.
            ads_wsp_helper->m_logf(ied_sdh_log_error, "HLDAE479E: Bind failed, because m_get_sysinfo() failed with error %d. Details: %.*s.", // JF 02.08.10: HLDAE478E -> HLDAE479E
				inl_ret, hstr_last_error.m_get_len(), hstr_last_error.m_get_ptr());
            return 100;
        }
        bog_sysinfo_done = (inl_ret == SUCCESS);
    }
    if ( (ach_userid == NULL) || (in_len_userid < 1)
    ||   (ach_pw_old == NULL) || (in_len_pw_old < 1)
    ||   (ach_pw_new == NULL) || (in_len_pw_new < 1) ) {
        hstr_last_error.m_set("HLDAPE444E: m_change_pwd called with invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD054D: Change password for '%.*s'.", in_len_userid, ach_userid);

    bool bo_ret = false;

    switch (ing_ldap_srv_type) {
        case ied_sys_ldap_opends: {
            // At first a bind must be done, to verify the old password.
            int inl_ret = m_bind(ach_userid, in_len_userid, ach_pw_old, in_len_pw_old, ied_auth_user);
            if (inl_ret != SUCCESS) {
                ds_hstring hstr_details = m_get_last_error();
                hstr_last_error.m_set("HLDAPE244E: Change password failed, because the user ");
                hstr_last_error.m_writef("'%.*s' could not be validated. Details: %s", in_len_userid, ach_userid, hstr_details.m_get_ptr());
                ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
                return 20;
            }

            //--------------------
            // Attribute userPassword
            //--------------------
            dsd_ldap_val dsl_val_pwd;
            memset(&dsl_val_pwd, 0, sizeof(dsd_ldap_val));
            dsl_val_pwd.ac_val        = const_cast<char*>(ach_pw_new);
            dsl_val_pwd.imc_len_val   = in_len_pw_new;
            dsl_val_pwd.iec_chs_val   = ied_chs_utf_8;

            dsd_ldap_attr dsl_attr_pwd;
            memset(&dsl_attr_pwd, 0, sizeof(dsd_ldap_attr));
            dsl_attr_pwd.ac_attr         = (char*)"userPassword";
            dsl_attr_pwd.imc_len_attr    = sizeof("userPassword")-1;
            dsl_attr_pwd.iec_chs_attr    = ied_chs_utf_8;
            dsl_attr_pwd.dsc_val         = dsl_val_pwd;

            dsd_ldap_attr_desc dsl_attr_desc;
            memset(&dsl_attr_desc, 0, sizeof(dsd_ldap_attr_desc));
            dsl_attr_desc.ac_dn               = const_cast<char*>(hstr_our_dn.m_get_ptr());
            dsl_attr_desc.imc_len_dn          = hstr_our_dn.m_get_len();
            dsl_attr_desc.iec_chs_dn          = ied_chs_utf_8;
            dsl_attr_desc.adsc_attr           = &dsl_attr_pwd;
            

            adsc_co_ldap.adsc_attr_desc   = &dsl_attr_desc;
            adsc_co_ldap.iec_co_ldap      = ied_co_ldap_modify;
            if ( (ach_base_add != NULL) && (in_len_base_add > 0) ) {
                adsc_co_ldap.dsc_add_dn.ac_str      = const_cast<char*>(ach_base_add);
                adsc_co_ldap.dsc_add_dn.imc_len_str = in_len_base_add;
            }
            else {
                adsc_co_ldap.dsc_add_dn.ac_str      = NULL;
                adsc_co_ldap.dsc_add_dn.imc_len_str = 0;
            }
            
            // Do the AUX here, because the structures (e.g. dsl_val_pwd) are locally setup.
            bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
            break;
        }
        case ied_sys_ldap_msad: {
            // Only MSAD: LDAP xsldap01.cpp provides a functionality for changing user's password.
            // This is done by an authentication using the old password, then the result
            // is parsed for the 'password expired'-message. Last the password is changed
            // under the administrator's control.

            adsc_co_ldap.iec_co_ldap    = ied_co_ldap_bind;
            adsc_co_ldap.iec_ldap_auth  = ied_auth_user_pwd_change;
            
            adsc_co_ldap.ac_userid      = const_cast<char*>(ach_userid);
            adsc_co_ldap.imc_len_userid = in_len_userid;
            adsc_co_ldap.iec_chs_userid = ied_chs_utf_8;
            if ( (ach_pw_old != NULL) && (in_len_pw_old) ) {
                adsc_co_ldap.ac_passwd      = const_cast<char*>(ach_pw_old);
                adsc_co_ldap.imc_len_passwd = in_len_pw_old;
            }
            else {
                adsc_co_ldap.ac_passwd      = NULL;
                adsc_co_ldap.imc_len_passwd = 0;
            }
            adsc_co_ldap.iec_chs_passwd = ied_chs_utf_8;

            adsc_co_ldap.ac_passwd_new      = const_cast<char*>(ach_pw_new);
            adsc_co_ldap.imc_len_passwd_new = in_len_pw_new;
            adsc_co_ldap.iec_chs_passwd_new = ied_chs_utf_8;

            if ( (ach_base_add != NULL) && (in_len_base_add > 0) ) {
                adsc_co_ldap.dsc_add_dn.ac_str      = const_cast<char*>(ach_base_add);
                adsc_co_ldap.dsc_add_dn.imc_len_str = in_len_base_add;
            }
            else {
                adsc_co_ldap.dsc_add_dn.ac_str      = NULL;
                adsc_co_ldap.dsc_add_dn.imc_len_str = 0;
            }

            bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
            break;
        }
        default: {
            hstr_last_error.m_set("m_change_pwd() failed: Invalid server type.");
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 3;
        }
    }

    // JF 30.03.11 Reset the additional base, we don't need it any more.
    // Otherwise it will be added by xsldapc01 every time.
    if ( (ach_base_add != NULL) && (in_len_base_add > 0) ) {
        adsc_co_ldap.dsc_add_dn.ac_str      = NULL;
        adsc_co_ldap.dsc_add_dn.imc_len_str = 0;
    }

    if (bo_ret == false) {
        hstr_last_error.m_set("HLDAE178E: Change password failed for user "); 
        hstr_last_error.m_writef("'%.*s'. Method returned false. Check, whether the server is running.", adsc_co_ldap.imc_len_userid, adsc_co_ldap.ac_userid);
		ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 4;
    }
    if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
        hstr_last_error.m_set("HLDAE177E: Change password failed for user ");
        hstr_last_error.m_writef("'%.*s' with error %d.", in_len_userid, ach_userid, adsc_co_ldap.iec_ldap_resp);
        if (adsc_co_ldap.ac_errmsg != NULL) {
            if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
            }
            else {
                hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
            }
        }
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 5;
    }

    
    hstr_our_dn.m_set(adsc_co_ldap.ac_dn, adsc_co_ldap.imc_len_dn);
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD055D: Password was changed for '%s'", hstr_our_dn.m_get_ptr());

    return SUCCESS;
}


/**Search LDAP server for a specified object class and insert it, if it is
 * not yet there. Attention: don't insert the object class into
 * MSActiveDirectory or Siemens DirX or when user does not want !
 * 
 * @param ahstr_oc [in] Name of the object class to be inserted.
 * @param ahstr_dn [in] DN of the item, to which object class shall be inserted.
 */
int ds_ldap::m_insert_objectclass(const ds_hstring* ahstr_oc, const ds_hstring* ahstr_dn, bool bo_insert_oc) {
    if ((ing_ldap_srv_type == ied_sys_ldap_msad) || (ing_ldap_srv_type == ied_sys_ldap_siemens) || (!bo_insert_oc)) {
        return SUCCESS;
    }
    
    if ( (ahstr_oc==NULL) || (ahstr_oc->m_get_len() < 1) || (ahstr_dn==NULL) || (ahstr_dn->m_get_len() < 1) ) {
        hstr_last_error.m_set("HLDAPE244E: m_insert_objectclass called with invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD056D: Insert object class '%s' to '%s'.", ahstr_oc->m_get_ptr(), ahstr_dn->m_get_ptr());

    ds_hvector<ds_attribute_string> dsl_v_objectclass(ads_wsp_helper);
    ds_hstring hstr_attrlist(ads_wsp_helper, "objectClass", (int)strlen("objectClass"));
    ds_hstring hstr_filter(ads_wsp_helper, "(objectClass=", (int)strlen("(objectClass="));
    hstr_filter.m_writef("%s)", ahstr_oc->m_get_ptr());
    int inl_ret = m_read_attributes(&hstr_attrlist, &hstr_filter, ahstr_dn, ied_sear_baseobject, &dsl_v_objectclass);
    if (inl_ret != SUCCESS) {
        return inl_ret+100;
    }

    // insert object class, if not there
    if (dsl_v_objectclass.m_size() == 0) {
        char* ach_attrname = (char*)"objectclass";

        dsd_ldap_attr dsl_attr;
        memset(&dsl_attr, 0, sizeof(dsd_ldap_attr));
        dsl_attr.ac_attr        = ach_attrname;
        dsl_attr.imc_len_attr   = (int)strlen(ach_attrname);
        dsl_attr.iec_chs_attr   = ied_chs_utf_8;
        dsl_attr.dsc_val.adsc_next_val = NULL;
        dsl_attr.dsc_val.ac_val        = const_cast<char*>(ahstr_oc->m_get_ptr());
        dsl_attr.dsc_val.imc_len_val   = ahstr_oc->m_get_len();
        dsl_attr.dsc_val.iec_chs_val   = ied_chs_utf_8;

        dsd_ldap_attr_desc dsl_attr_desc;
        memset(&dsl_attr_desc, 0, sizeof(dsd_ldap_attr_desc));
        dsl_attr_desc.ac_dn               = const_cast<char*>(ahstr_dn->m_get_ptr());
        dsl_attr_desc.imc_len_dn          = ahstr_dn->m_get_len();
        dsl_attr_desc.iec_chs_dn          = ied_chs_utf_8;
        dsl_attr_desc.adsc_attr           = &dsl_attr;

        adsc_co_ldap.adsc_attr_desc   = &dsl_attr_desc;
        adsc_co_ldap.iec_co_ldap      = ied_co_ldap_modify; //ied_co_ldap_add; // ied_co_ldap_modify;
        
        bool bo_ret = ads_wsp_helper->m_cb_ldap_request( &adsc_co_ldap );
        if (bo_ret == false) {
            hstr_last_error.m_set("m_insert_objectclass failed: method returned false");
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 3;
        }
        if (adsc_co_ldap.iec_ldap_resp != ied_ldap_success) {
            hstr_last_error.m_set("m_insert_objectclass failed with error ");
            hstr_last_error.m_writef("%d.", adsc_co_ldap.iec_ldap_resp);
            if (adsc_co_ldap.ac_errmsg != NULL) {
                if (adsc_co_ldap.imc_len_errmsg == -1) { // means: adsc_co_ldap.ac_errmsg is zero-terminated
                    hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %s.", __LINE__, adsc_co_ldap.ac_errmsg);
                }
                else {
                    hstr_last_error.m_writef(" ds-ldap l%05d LDAP message: %.*s.", __LINE__, adsc_co_ldap.imc_len_errmsg, adsc_co_ldap.ac_errmsg);
                }
            }
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 4;
        }
        ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD057D: Object class '%s' inserted to '%s'.", ahstr_oc->m_get_ptr(), ahstr_dn->m_get_ptr());
    }
    else {
        ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD058D: Object class '%s' already existed at '%s'.", ahstr_oc->m_get_ptr(), ahstr_dn->m_get_ptr());
    }

    return SUCCESS;
}


/**Cut the prefix from a string. The prefix is the part until the first '=' (inclusive the '=').
 * <br>Example: "cn=frank" -> "frank".
 * @param ahstr_with_prefix     [in] String, where to cut off the prefix.
 * @param ahstr_without_prefix [out] String without the prefix.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 * public method
 */
int ds_ldap::m_cut_prefix(const ds_hstring* ahstr_with_prefix, ds_hstring* ahstr_without_prefix) {
    if ( (ahstr_with_prefix==NULL) || (ahstr_with_prefix->m_get_len() < 1) || (ahstr_without_prefix==NULL) ) {
        hstr_last_error.m_set("HLDAPE157E: m_cut_prefix called with invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    int in_pos = ahstr_with_prefix->m_find_first_of("=");
    if (in_pos == -1) {
        // No prefix found. Nothing else to do.
        ahstr_without_prefix->m_write(ahstr_with_prefix);
        return SUCCESS;
    }
    ahstr_without_prefix->m_write(ahstr_with_prefix->m_substring(in_pos + 1));
    return SUCCESS;
}

/**Get the first token from a DN.<br>
 * Example: "cn=frank,cn=users,dc=hob,dc=de" -> "cn=frank".
 * @param ahstr_dn [in] DN of the item.
 * @param ahstr_first_token [out] Will hold the first part of the DN.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 * public method
 */
int ds_ldap::m_get_first_token_of_dn(const ds_hstring* ahstr_dn, ds_hstring* ahstr_first_token) {
    if ( (ahstr_dn==NULL) || (ahstr_dn->m_get_len() < 1) || (ahstr_first_token==NULL) ) {
        hstr_last_error.m_set("HLDAPE144E: m_get_first_token_of_dn called with invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD060D: m_get_first_token_of_dn() '%s'.", ahstr_dn->m_get_ptr());

    ds_hvector<ds_hstring> dsl_tokens(ads_wsp_helper);
    int in_ret = m_tokenize_dn(ahstr_dn, &dsl_tokens, false, true);
    if (in_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("m_tokenize_dn() failed with error %d.", in_ret);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    if (dsl_tokens.m_size() < 1) {
        hstr_last_error.m_set("dsl_tokens.m_size() < 1");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 3;
    }

    // First token is the requested one.
    ahstr_first_token->m_set(dsl_tokens.m_get_first());
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD061D: m_get_first_token_of_dn() '%s' returns '%s'.", ahstr_dn->m_get_ptr(), ahstr_first_token->m_get_ptr());

    return SUCCESS;
}


/**Collect for a given item all DNs (the item's DN itself, and then all parents).<br>
 * Example: "cn=frank,cn=users,dc=hob,dc=de"
 * The returned vector will contain (longest DN first!): "cn=frank,cn=users,dc=hob,dc=de", "cn=users,dc=hob,dc=de", "dc=hob,dc=de", "dc=de"
 * @param ahstr_dn [in] DN of the item.
 * @param adsl_v_dns [out] Vector, which holds the DNs.
 * @param bo_tokenize_base [in] If false, the base will not be splitted, if the base contains a separator. The example case will then not return "dc=de".
 * @param bo_is_comlete_dn [in] false means, that the base is missing.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_get_tree_dns(const ds_hstring* ahstr_dn, ds_hvector<ds_hstring>* adsl_v_dns, bool bo_tokenize_base, bool bo_is_comlete_dn) {
    if ( (ahstr_dn == NULL) || (ahstr_dn->m_get_len() < 1) || (adsl_v_dns == NULL) ) {
        hstr_last_error.m_set("HLDAPE344E: m_get_tree_dns() called with invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD062D: m_get_tree_dns() for '%s'. bo_tokenize_base=%d. bo_is_comlete_dn=%d", ahstr_dn->m_get_ptr(), bo_tokenize_base, bo_is_comlete_dn);

    ds_hvector<ds_hstring> dsl_tokens(ads_wsp_helper);
    int in_ret = m_tokenize_dn(ahstr_dn, &dsl_tokens, bo_tokenize_base, bo_is_comlete_dn);
    if (in_ret != SUCCESS) {
        hstr_last_error.m_reset();
        hstr_last_error.m_writef("m_tokenize_dn() failed with error %d.", in_ret);
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 2;
    }

    // Concatenate the tokens to DNs
    for (HVECTOR_FOREACH(ds_hstring, adsl_cur, dsl_tokens)) {
        ds_hstring hstr_dn(ads_wsp_helper, "");
        for(const dsd_hvec_elem<ds_hstring>* adsl_cur2=adsl_cur; adsl_cur2 != NULL; adsl_cur2=adsl_cur2->ads_next) {
            if(hstr_dn.m_get_len() != 0)
                hstr_dn.m_write(",");
            hstr_dn += adsl_cur2->dsc_element;
        }
        adsl_v_dns->m_add(hstr_dn);
    }

    bool bo_log_details = true;
    if (bo_log_details) {
        ds_hstring hstr_log(ads_wsp_helper, 2000);
        hstr_log.m_write("HLDAD063D: m_get_tree_dns() returns ");
        int in_pos = 0;
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur, *adsl_v_dns)) {
            hstr_log.m_writef(" Index: %d DN: %s.", in_pos, HVECTOR_GET(adsl_cur).m_get_ptr());
            in_pos++;
        }
        ads_wsp_helper->m_log(ied_sdh_log_details, hstr_log.m_const_str());
    }

    return SUCCESS;
}


/**Tokenize a given DN.<br>
 * Example: "cn=frank,cn=users,dc=hob,dc=de"
 * The returned vector will contain (longest DN first!): "cn=frank,cn=users,dc=hob,dc=de", "cn=users,dc=hob,dc=de", "dc=hob,dc=de", "dc=de"
 * @param ahstr_dn [in] DN of the item.
 * @param adsl_tokens [out] Vector, which holds the tokens.
 * @param bo_tokenize_base [in] If false, the base will not be splitted, if the base contains a separator. The example case will then not return "dc=de".
 * @param bo_is_comlete_dn [in] false means, that the base is missing.
 * @return 0 if successful. In case of error an explicit error number is returned. A detailed error message can be retrieved with m_get_last_error().
 */
int ds_ldap::m_tokenize_dn(const ds_hstring* ahstr_dn, ds_hvector<ds_hstring>* adsl_tokens, bool bo_tokenize_base, bool bo_is_comlete_dn) {
    if ( (ahstr_dn == NULL) || (ahstr_dn->m_get_len() < 1) || (adsl_tokens == NULL) ) {
        hstr_last_error.m_set("HLDAPE124E: m_tokenize_dn() called with invalid parameter.");
        ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
        return 1;
    }
    ads_wsp_helper->m_logf(ied_sdh_log_details, "HLDAD064D: m_tokenize_dn() for '%s'. bo_tokenize_base=%d. bo_is_comlete_dn=%d", ahstr_dn->m_get_ptr(), bo_tokenize_base, bo_is_comlete_dn);


    // Check, whether the DN matches the base; case-insensitive comparison!
    int in_pos_base = ahstr_dn->m_search_ic(hstrg_base);
    if ( (bo_is_comlete_dn)
    &&   ( (in_pos_base == -1) || (!ahstr_dn->m_ends_with_ic(hstrg_base)) ) ) {
          hstr_last_error.m_reset();
          hstr_last_error.m_writef("Root '%s' does not match the context/dn '%s'", hstrg_base.m_get_ptr(), ahstr_dn->m_get_ptr());
          ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
          return 2;
    }

    dsd_const_string hstrl_dn(ahstr_dn->m_const_str());
    if (!bo_tokenize_base) {
        if (in_pos_base == 0) { // JF 26.11.10 The delivered DN is the base and we shall not tokenize it -> we are done.
            adsl_tokens->m_add3(hstrl_dn);
            return SUCCESS;
        }

        hstrl_dn = hstrl_dn.m_substring(0, in_pos_base-1);
    }

    char ch, ch_next;
    ds_hstring hstr_token(ads_wsp_helper);
    int in_len = hstrl_dn.m_get_len();
    for (int i=0; i<in_len; i++) {
        ch = hstrl_dn[i];

        // backslash can be used as escape character !!
        if (ch == '\\') {
            // check the next character
            ch_next = hstrl_dn[i+1];
            // If next character is a backslash, the first backslash was used
            // as escape character -> it's ok
            if (ch_next == '\\') {
                hstr_token.m_write(&ch, 1);
                hstr_token.m_write(&ch, 1);
                i++; // hop over these two backslashes
            }
            // If next character is a comma or semi-colon (separating characters in LDAP), the
            // backslash was used as escape character -> don't ignore the backslash and don't tokenize !!
            else if ( (ch_next == ',') || (ch_next == ';') ) {
                hstr_token.m_write("\\", 1);
                hstr_token.m_write(&ch_next, 1);
                i++; // hop over '\,'
            }
            else { // Backslash was no escape character -> append to token
                hstr_token.m_write(&ch, 1);
            }
            continue;
        }

        // a comma is meant as a separator -> the token is complete
        if (ch == ',') {
            hstr_token.m_trim(" ", true, true);
            adsl_tokens->m_add(hstr_token);
            
            // setup new string
            hstr_token.m_reset();
            
            continue;
        }
        
        // character is just a normal character -> put to stringbuffer
        hstr_token.m_write(&ch, 1);
    }

    // don't forget last token
    if (hstr_token.m_get_len() > 0) {
        hstr_token.m_trim(" ", true, true);
        adsl_tokens->m_add(hstr_token);
    }
    
    if (!bo_tokenize_base) { // add root as last element
        if (hstrg_base.m_get_len() > 0) { // Ticket[14316]: add root only, if it exists (may be empty in case of Novell E-dir)
            adsl_tokens->m_add(hstrg_base);
        }
    }

    bool bo_log_details = true;
    if (bo_log_details) {
        ds_hstring hstr_log(ads_wsp_helper, 2000);
        hstr_log.m_write("HLDAD066D: m_tokenize_dn() returns ");
        int in_pos = 0;
        for (HVECTOR_FOREACH(ds_hstring, adsl_cur, *adsl_tokens)) {
            hstr_log.m_writef(" Index: %d DN: %s.", in_pos, HVECTOR_GET(adsl_cur).m_get_ptr());
            in_pos++;
        }
        ads_wsp_helper->m_log(ied_sdh_log_details, hstr_log.m_const_str());
    }

    return SUCCESS;
}


int ds_ldap::m_convert_to_vector(dsd_ldap_attr_desc* adsl_attr_desc_curr, ds_hvector<ds_attribute_string>* adsl_v_attributes) {
    // setup the return
    adsl_attr_desc_curr = adsc_co_ldap.adsc_attr_desc;

    // the returned data are organized as follows:
    // chain of dsd_ldap_attr_desc, which hold DN-info, next-pointer and dsd_ldap_attr
    // chain of dsd_ldap_attr, which hold name-info, next-pointer and dsd_ldap_val
    // chain of dsd_ldap_val, which hold value-info and next-pointer
    dsd_ldap_attr* adsl_attr = NULL;
    dsd_ldap_val* adsl_val = NULL;
    while (adsl_attr_desc_curr) {
        // up to now we support only charset UTF8 in the LDAP-response
        if (adsl_attr_desc_curr->iec_chs_dn != ied_chs_utf_8) {
            hstr_last_error.m_set("HLDAPE781E: m_convert_to_vector: LDAP response is not in UTF8.");
            ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
            return 40;
        }
        // get DN
        ds_hstring hstr_dn(ads_wsp_helper, adsl_attr_desc_curr->ac_dn, adsl_attr_desc_curr->imc_len_dn);

        adsl_attr = adsl_attr_desc_curr->adsc_attr;
        while (adsl_attr) { // fill return vector
            // up to now we support only charset UTF8 in the LDAP-response
            if (adsl_attr->iec_chs_attr != ied_chs_utf_8) {
                hstr_last_error.m_set("HLDAPE711E: m_convert_to_vector: LDAP response is not in UTF8.");
                ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
                return 41;
            }

            adsl_val = &adsl_attr->dsc_val;

            // Write single or multi-valued values to a ds_attribute_string.
            ds_attribute_string dsl_attrstr(ads_wsp_helper);
            dsl_attrstr.m_set_dn(&hstr_dn);
            dsl_attrstr.m_set_name(adsl_attr->ac_attr, adsl_attr->imc_len_attr);
            int inl_ret = m_copy_val_to_attrstring(adsl_val, &dsl_attrstr);
            if (inl_ret != SUCCESS) {
                hstr_last_error.m_reset();
                hstr_last_error.m_writef("HLDAPE782E: m_copy_val_to_attrstring failed with error %d.", inl_ret);
                ads_wsp_helper->m_log(ied_sdh_log_error, hstr_last_error.m_const_str());
                return 42;
            }

            // Some values were read in -> put this ds_attribute_string to return-vector
            if (dsl_attrstr.m_get_values().m_size() > 0) {
                adsl_v_attributes->m_add(dsl_attrstr);
            }

            adsl_attr = adsl_attr->adsc_next_attr;
        } // while (adsl_attr)
        adsl_attr_desc_curr = adsl_attr_desc_curr->adsc_next_attr_desc;
    }

    return SUCCESS;
}

int ds_ldap::m_copy_val_to_attrstring(dsd_ldap_val* adsl_val, ds_attribute_string* adsl_attrstring) {
    // write single or multi-valued values to the attribute
    while (adsl_val) {
        // up to now we support only charset UTF8 in the LDAP-response
        if (adsl_val->iec_chs_val != ied_chs_utf_8) {
            return 1;
        }
        ds_hstring hstr_val(ads_wsp_helper, adsl_val->ac_val, adsl_val->imc_len_val);
        adsl_attrstring->m_add_to_values(&hstr_val);
        adsl_val = adsl_val->adsc_next_val;
    } // while (adsl_val)
    return SUCCESS;
}



/**Determine, whether an attribute is in binary format.<br>
 * @param ahstr_attr_name [in] Name of the attribute.
 * @return true=Attribute is a binary attribute in LDAP; otherwise false.
 */
bool ds_ldap::m_is_binary(const ds_hstring* ahstr_attr_name)
{
    //-----------------------------------------------------------------------------------------------------------------------//
    // Informations to LDAP Attributes                                                                                       //
    // http://java.sun.com/products/jndi/tutorial/ldap/misc/attrs.html                                                       //
    // An LDAP attribute can have a single value or multiple, unordered values. Whether an attribute is allowed to have more //
    // than one value is dictated by the attribute's definition in the directory's schema. Both single and multivalued       //
    // attributes are represented in the JNDI as an Attribute.                                                               //
    // The JNDI is very flexible in how attribute values can be represented because such values are declared as              //
    // java.lang.Object. When you use the JNDI to access or update attributes stored in a particular directory, the types of //
    // the attribute values depend on the directory and to some extent, on the corresponding service provider. For the LDAP  //
    // directory, Sun's LDAP provider represents attribute values as either java.lang.String or byte[]. byte arrays are used //
    // to represent attribute values with nonstring attribute syntaxes. Strings are used to represent the values of all      //
    // other syntaxes.                                                                                                       //
    // For an arbitrary attribute, no programmatic way is available to determine whether its syntax is nonstring. Manual     //
    // ways are available, of course, and involve looking up the attribute and its syntax in documents such as RFC 2256. The //
    // LDAP service provider has a built-in list of attribute names that it knows contain nonstring values and allows        //
    // clients to add to that list. The following table gives that built-in list.                                            //
    // When you read one of these attributes from the LDAP directory, its value will be of type byte[].                      //
    //                                                                                                                       //
    // Attribute Name                       Attribute OID                                                                    //
    // photo                                0.9.2342.19200300.100.1.7                                                        //
    // personalSignature                    0.9.2342.19200300.100.1.53                                                       //
    // audio                                0.9.2342.19200300.100.1.55                                                       //
    // jpegPhoto                            0.9.2342.19200300.100.1.60                                                       //
    // javaSerializedData                   1.3.6.1.4.1.42.2.27.4.1.8                                                        //
    // thumbnailPhoto                       1.3.6.1.4.1.1466.101.120.35                                                      //
    // thumbnailLogo                        1.3.6.1.4.1.1466.101.120.36                                                      //
    // userPassword                         2.5.4.35                                                                         //
    // userCertificate                      2.5.4.36                                                                         //
    // cACertificate                        2.5.4.37                                                                         //
    // authorityRevocationList              2.5.4.38                                                                         //
    // certificateRevocationList            2.5.4.39                                                                         //
    // crossCertificatePair                 2.5.4.40                                                                         //
    // x500UniqueIdentifier                 2.5.4.45                                                                         //
    //-----------------------------------------------------------------------------------------------------------------------//

    // Go thru the hard-coded list of the names of known binary attribute. Check whether the passed name is included.
    int in_compare = 0; // Result of the compare.
    int in_idx = 0;
    while (achr_binary_attrs[in_idx] != NULL) {
        BOOL bo_ret = m_cmpi_vx_vx( &in_compare,
                               const_cast<char*>(ahstr_attr_name->m_get_ptr()), ahstr_attr_name->m_get_len(),
                               ied_chs_utf_8,
                               (void*)achr_binary_attrs[in_idx],
                               (int)strlen(achr_binary_attrs[in_idx]),
                               ied_chs_utf_8 );
        if ( bo_ret == TRUE && in_compare == 0 ) {
            // We found the attribute name.
            return true;
        }
        in_idx++;
    }

    return false;
}

