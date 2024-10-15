#include "ds_state.h"
#include "ds_http_header.h"

ds_state::ds_state(void)
	: in_accept_encoding(ds_http_header::ien_ce_identity)
{
}

ds_state::~ds_state(void)
{
}

/*! \brief Reset the encoding
 *
 * @ingroup creator
 *
 * clear variables
 */
int ds_state::m_reset(void)
{
    in_accept_encoding = ds_http_header::ien_ce_identity;


    return 0;
}


