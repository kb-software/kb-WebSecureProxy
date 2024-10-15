#ifndef _AT_RESOURCES_H
#define _AT_RESOURCES_H

#ifndef HL_UNIX
    #pragma warning(disable:4428)
    #pragma warning(disable:4566)
#endif

enum ied_wspat_resource {
    ied_wspat_res_auth_user_pwd,          // enter userid and password
    ied_wspat_res_auth_pwd,               // enter password
    ied_wspat_res_auth_challenge,         // enter challenge
    ied_wspat_res_auth_failed,            // auth failed
    ied_wspat_res_auth_kickout,           // kick out session
    ied_wspat_res_auth_no_role,           // no role found
    ied_wspat_res_auth_change_pwd,        // change password
    ied_wspat_res_auth_pwd_exp_days,      // password will expire in x days
    ied_wspat_res_auth_pwd_exp_tomorrow,  // password will expire tomorrow
    ied_wspat_res_auth_pwd_exp_today,     // password will expire today
    ied_wspat_res_server_entry_not_found, // no server entry found
    ied_wspat_res_connect_failed,         // connect to server failed
};

/*+---------------------------------------------------------------------+*/
/*| english resources:                                                  |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_wspat_res_en[] = {
    "HOB WebSecureProxy Authentication\r\nEnter User ID and Password\r\n",
    "HOB WebSecureProxy Authentication\r\nEnter Password\r\n",
    "HOB WebSecureProxy Authentication\r\nEnter Challenge\r\n",
    "HOB WebSecureProxy Authentication Failed\r\nEnter User ID and Password\r\n",
    "There exists already a session for your username.\r\nReenter your password to kickout this session\r\n",
    "No matching role found.\r\n",
    "Your Password has expired. Please choose a new password.\r\n",
    "Your Password will expire in %d days.\r\n Do you want to change it now?\r\n",
    "Your Password will expire tomorrow.\r\n Do you want to change it now?\r\n",
    "Your Password will expire today.\r\n Do you want to change it now?\r\n",
	 "The server entry does not exist.\r\n",
	 "The connection to the server entry has failed.\r\n",
};

/*+---------------------------------------------------------------------+*/
/*| spanish resources:                                                  |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_wspat_res_es[] = {
	dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
	 dsd_const_string::m_null(),
	 dsd_const_string::m_null(),
};

/*+---------------------------------------------------------------------+*/
/*| french resources:                                                   |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_wspat_res_fr[] = {
    "Authentification HOB WebSecureProxy\r\nentrez code d\302\264utilisateur et mot de passe\r\n",
    "Authentification HOB WebSecureProxy\r\nentrez mot de passe\r\n",
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
	 dsd_const_string::m_null(),
	 dsd_const_string::m_null(),
};

/*+---------------------------------------------------------------------+*/
/*| german resources:                                                   |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_wspat_res_de[] = {
    "HOB WebSecureProxy Anmeldung\r\nGeben Sie User-ID und Passwort ein\r\n",
    "HOB WebSecureProxy Anmeldung\r\nGeben Sie das Passwort ein\r\n",
    "HOB WebSecureProxy Anmeldung\r\nGeben Sie die Challenge ein\r\n",
    "HOB WebSecureProxy Anmeldung fehlgeschlagen\r\nGeben Sie User-ID und Passwort ein\r\n",
    "Es exististiert bereits eine Sitzung mit Ihrem Benutzernamen.\r\nGeben Sie Ihr Passwort erneut ein, um die Sitzung zu \uc3bcbernehmen\r\n",
    "Es wurde keine passende Rolle gefunden.\r\n",
    "Ihr Passwort ist abgelaufen. Bitte geben Sie ein neues Passwort ein.\r\n",
    "Ihr Passwort wird in %d Tagen ablaufen.\r\n Wollen Sie es jetzt \uc3a4ndern?\r\n",
    "Ihr Passwort wird morgen ablaufen.\r\n Wollen Sie es jetzt \uc3a4ndern?\r\n",
    "Ihr Passwort wird heute ablaufen.\r\n Wollen Sie es jetzt \uc3a4ndern?\r\n",
	 "Der Server-Eintrag existiert nicht.\r\n",
	 dsd_const_string::m_null(),
};

/*+---------------------------------------------------------------------+*/
/*| italien resources:                                                  |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_wspat_res_it[] = {
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
	 dsd_const_string::m_null(),
	 dsd_const_string::m_null(),
};

/*+---------------------------------------------------------------------+*/
/*| dutch resources:                                                    |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_wspat_res_nl[] = {
    "HOB WebSecureProxy Aanmelding\r\nVul Userid en paswoord in\r\n",
    "HOB WebSecureProxy Aanmelding\r\nVul paswoord in\r\n",
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
	 dsd_const_string::m_null(),
};

/*+---------------------------------------------------------------------+*/
/*| chinese resources:                                                  |*/
/*+---------------------------------------------------------------------+*/
static const dsd_const_string achr_wspat_res_zh[] = {
    "HOB WebSecureProxy\u8ba4\u8bc1\r\n\u8f93\u5165\u7528\u6237\u53f7\u548c\u5bc6\u7801\r\n",
    "HOB WebSecureProxy\u8ba4\u8bc1\r\n\u8f93\u5165\u5bc6\u7801\r\n",
    dsd_const_string::m_null(),
    "\u8ba4\u8bc1\u51fa\u9519\r\n\u91cd\u65b0\u8ba4\u8bc1\r\n\u8f93\u5165\u7528\u6237\u53f7\u548c\u5bc6\u7801\r\n",
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
    dsd_const_string::m_null(),
	 dsd_const_string::m_null(),
};


/*+---------------------------------------------------------------------+*/
/*| get resources:                                                      |*/
/*+---------------------------------------------------------------------+*/
dsd_const_string m_get_resource( ied_wspat_language ienp_lang, ied_wspat_resource ienp_message )
{
    // initialize some variables:
	dsd_const_string achl_message;

    // select language:
    switch ( ienp_lang ) {
        case ied_wspat_lang_en:
            achl_message = achr_wspat_res_en[ienp_message];
            break;

        case ied_wspat_lang_es:
            achl_message = achr_wspat_res_es[ienp_message];
            break;

        case ied_wspat_lang_fr:
            achl_message = achr_wspat_res_fr[ienp_message];
            break;

        case ied_wspat_lang_de:
            achl_message = achr_wspat_res_de[ienp_message];
            break;

        case ied_wspat_lang_it:
            achl_message = achr_wspat_res_it[ienp_message];
            break;

        case ied_wspat_lang_nl:
            achl_message = achr_wspat_res_nl[ienp_message];
            break;

        case ied_wspat_lang_zh:
            achl_message = achr_wspat_res_zh[ienp_message];
            break;
    }

    // if a resource is not defined in the current language, we select english as default:
	if ( achl_message.m_is_null() ) {
        achl_message = achr_wspat_res_en[ienp_message];
    }

    return achl_message;
}

#endif // _AT_RESOURCES_H
