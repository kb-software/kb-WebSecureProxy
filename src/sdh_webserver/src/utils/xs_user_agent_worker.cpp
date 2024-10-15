#ifdef _DEBUG
#include <stdio.h>
#endif

#include "xs_user_agent_worker.h"

/** if user agent contains one of those strings means we have a mobile device. */
static const char * cstrrs_mobile_strings [] = {
    "android",
    "midp",
    "tablet",
    "ipad",
    "iphone",
    "ipod",
    "itunes",
    "samsung",
    "sie",
    "mobi",
    "playbook",
    "blackberry",
    "mobile",
    "cricket",
    "dell",
    "iemobile",
    "phone",
    "kindle",
    "lg",
    "lge",
    "mot",
    "smartphone",
    "nintendo",
    "nokia",
    "mini",
    "symbianos",
    "symbian",
    "symbos",
    "nokian",
    "nokiax",
    "nokiac",
    "spv",
    "palm",
    "palmsource",
    "palmos",
    "mobileexplorer",
    "reqwirelessweb",
    "sonyericsson",
    "sonyericssonk",
    "psp",
    "portable",
    "sprint",
    "cros",
    "pie",
    "vodafone"
};

static const int cins_char_diff = 'a'-'A';  ///< offset lowercase-uppercase

/** names of portlets, that should be hidden on mobile devices. */
static const char * cstrrs_portlets_blocked_mobile[] = {
    "ppptunnel",
    "hobphone",
    "admin",
    "jterm",
    "jwtsa",
    "wspuc"
};

static const int cins_pbm_num = sizeof(cstrrs_portlets_blocked_mobile)/sizeof(char*);  ///< length of "cstrrs_portlets_blocked_mobile" array

/** token saves start and end position of a token on user agent string. */
struct ds_token
{
    char *  achc_start;          ///< start of token
    char *  achc_end;            ///< end of token
};



/**
* checks if this user agent belongs to a mobile device.
*/
static int m_is_mobile(struct ds_token * adsp_token_list, int inp_num_tokens);

#ifdef _DEBUG
/**
* just prints out all tokens.
*/
void m_debug_print(struct ds_token * adsp_token_list, int inp_num_tokens)
{
    char * achl_current;
    int inl_i;

    printf("--------------------------------------------------------\n");
    for (inl_i = 0; inl_i < inp_num_tokens; inl_i++)
    {
        achl_current = adsp_token_list[inl_i].achc_start;

        while (achl_current < adsp_token_list[inl_i].achc_end)
        {
            printf("%c", * achl_current);
            achl_current++;
        }
        printf("\n");
    }
    printf("--------------------------------------------------------\n");
}
#endif


/**
* this method takes a user agent string and its length and returns a bitfield as int
*/
int m_check_user_agent(const char * cachp_user_agent, const int cinp_length)
{
    int inl_ret = UA_CHECKED;            // return value. here we set first bit, which means we have checked this client's user agent
    struct ds_token dsrl_tokens[100];    // array of tokens (longest user agent had 23 tokens so 100 should be preatty safe)
    int inl_current_token = 0;           // index of current or number of tokens found
    int inl_i;                           // working index.
    int bol_in_token = 0;                // controls if we are currently in token
    char chl_char;                       // working variable ;P

    //----- collecting tokens ------------------------------------

    for (inl_i = 0; inl_i < cinp_length; inl_i++)
    {
        chl_char = cachp_user_agent[inl_i];

        if (!bol_in_token)  // if we are not in a token and find a letter -> means we have found a new token
        {
            if((chl_char >= 'A' && chl_char <= 'Z') || (chl_char >= 'a' && chl_char <= 'z'))
            {
                bol_in_token = 1; // means true
                dsrl_tokens[inl_current_token].achc_start = (char *)(cachp_user_agent+inl_i);
            }
        }
        else   // if we are in token and found an nonletter -> means we have left token.
        {
            if(!(chl_char >= 'A' && chl_char <= 'Z') && !(chl_char >= 'a' && chl_char <= 'z'))
            {
                bol_in_token = 0;  // means false
                dsrl_tokens[inl_current_token].achc_end = (char *)(cachp_user_agent+inl_i);
                inl_current_token++;
            }
        }
    }

    // if UA string ended with a letter, we never had chance to set the end pointer of last token.
    // and current token should point to one after the last token, what happens if there was a nonletter on last position.
    // here we correct this behavior.
    if (bol_in_token)
    {
        dsrl_tokens[inl_current_token].achc_end = (char *)(cachp_user_agent+inl_i);
        inl_current_token++;
    }

    //----- checks -----------------------------------------------


#ifdef _DEBUG
    //m_debug_print(dsrl_tokens, inl_current_token);  // just debug. don't forget to comment it out in live version
#endif

    //---- check for mobile device ----------------------------------------------------------

    if (m_is_mobile(dsrl_tokens, inl_current_token))   // if it is a mobile device -> we set bit for mobile.
    {
        inl_ret = inl_ret + UA_MOBILE;
    }


    return inl_ret;
}


/**
* checks if this user agent belongs to a mobile device.
*/
static int m_is_mobile(struct ds_token * adsp_token_list, int inp_num_tokens)
{
    int inl_num_mobile = sizeof(cstrrs_mobile_strings)/sizeof(char *);   // number of mobile strings
    int inl_it;                                                          // index for tokens
    int inl_ims;                                                         // index for mobile strings
    int inl_i;                                                           // index
    char * strl_mob_string;                                              // current mobile string

    for (inl_ims = 0; inl_ims  < inl_num_mobile; inl_ims ++)
    {
        strl_mob_string = (char*)cstrrs_mobile_strings[inl_ims];

        for (inl_it = 0; inl_it < inp_num_tokens; inl_it++)
        {
            for (inl_i = 0;
                strl_mob_string[inl_i] != 0 &&                                       // this string has not ended
                &adsp_token_list[inl_it].achc_start[inl_i] < adsp_token_list[inl_it].achc_end // and we are not at end of token
                ; inl_i++)
            {
                if (!(strl_mob_string[inl_i] == adsp_token_list[inl_it].achc_start[inl_i] ||              // lower case
                    strl_mob_string[inl_i] - cins_char_diff == adsp_token_list[inl_it].achc_start[inl_i]  // upper case
                ))
                    break;
            }

            if (strl_mob_string[inl_i] == 0 &&                                          // string has ended
                &adsp_token_list[inl_it].achc_start[inl_i] == adsp_token_list[inl_it].achc_end)  // and token has ended
            {
#ifdef _DEBUG
                //printf(strl_mob_string);  // debug print if you need to know why this device was chosen as mobile
                //printf("\n");
#endif
                return 1; // return true
            }
        }
    }

    return 0;  // return false
}

/**
* this method decides if a portlet should be hidden on this device.
*
* @param ibp_portlet_filter  bitfield returned by m_check_user_agent()
* @param strp_portlet_name   name of portlet
* @param inp_name_length     length of portlet name.
*
* @return 1 if portlet should be hidden,
*         0 otherwise.
*/
int m_is_portlet_to_hide(int ibp_portlet_filter, char * strp_portlet_name, int inp_name_length)
{
    int inl_i, inl_j;    // loop indexes
    char * str_s;        // working variable

    //----------------------------------------

    if(ibp_portlet_filter == 0 || ibp_portlet_filter == 1)  // 0 means we haven't checked yet, 1 means we have checked,
                                                            // but there was mothing to complain.
        return 0;  // in these cases all availiable portlets should be shown.


    if((ibp_portlet_filter & UA_MOBILE) == UA_MOBILE)    // we have a mobile device
    {
        for(inl_i = 0; inl_i < cins_pbm_num; inl_i++)  // loop over all blocked portlets
        {
            str_s = (char *)cstrrs_portlets_blocked_mobile[inl_i];

            for(inl_j = 0; inl_j < inp_name_length && str_s[inl_j] != 0; inl_j++)
            {
                if(str_s[inl_j] != strp_portlet_name[inl_j])
                    break;
            }

            if(inl_j == inp_name_length && str_s[inl_j] == 0)
                return 1;  // means hide this portlet
        }
    }
    //------------------------------------------------------

    // here we might add other reasons for hiding a portlet.

    //------------------------------------------------------

    return 0;  // means we haven't found any reason to hide this portlet.
}
