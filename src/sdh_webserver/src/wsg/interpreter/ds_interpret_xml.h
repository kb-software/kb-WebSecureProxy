/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_interpret_xml                                                      |*/
/*|                                                                         |*/
/*| DESCRIPTION:                                                            |*/
/*| ============                                                            |*/
/*|   this class gets xml data from webserver, changes all links, and       |*/
/*|   gives data back to webserver                                          |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   Januar 2008                                                           |*/
/*|                                                                         |*/
/*| VERSION:                                                                |*/
/*| ========                                                                |*/
/*|   0.1                                                                   |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

#ifndef DS_INTERPRET_XML_H
#define DS_INTERPRET_XML_H
/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_interpret.h"
#include <ds_hstring.h>

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/*! \brief Interprets XML data.
 *
 * @ingroup dataprocessor
 *
 * This class gets xml data from the webserver, changes all links, and gives 
 * the modified data back to the webserver.
 */
class ds_interpret_xml : public ds_interpret
{
public:
    //! Constructor.
    ds_interpret_xml(void);
    //! Destructor.
    ~ds_interpret_xml(void);
    //functions:
	//! Processes XML data.
    int  m_process_data( );
};
#endif // DS_INTERPRET_XML_H
