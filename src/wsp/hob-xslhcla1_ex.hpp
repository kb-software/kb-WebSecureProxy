#ifndef __HOB__XSLHCLA1_EX__HPP
#define __HOB__XSLHCLA1_EX__HPP

#include "hob-xslhcla1.hpp"
#if defined(WIN32) || defined(WIN64)
#include <windows.h>
#endif

class dsd_hcla_critsect_1_ex : public dsd_hcla_critsect_1 {                 /* class for critical sect */
	class dsd_scoped_enter_ptr {
		dsd_hcla_critsect_1* adsc_obj;
	public:
		inline dsd_scoped_enter_ptr(dsd_hcla_critsect_1* adsp_obj) : adsc_obj(adsp_obj) {
			if (adsc_obj)
				adsc_obj->m_enter();
		}
		inline ~dsd_scoped_enter_ptr() {
			if (adsc_obj)
				adsc_obj->m_leave();
		}
	};
	class dsd_scoped_enter_ref {
		dsd_hcla_critsect_1& dsc_obj;
      dsd_scoped_enter_ref& operator =(dsd_scoped_enter_ref& );
	public:
		inline dsd_scoped_enter_ref(dsd_hcla_critsect_1& dsp_obj) : dsc_obj(dsp_obj) {
			dsc_obj.m_enter();
		}
		inline ~dsd_scoped_enter_ref() {
			dsc_obj.m_leave();
		}
	};
public:
    inline dsd_hcla_critsect_1_ex() {
        m_create();
    }
    inline ~dsd_hcla_critsect_1_ex() {
        m_close();
    }
	typedef dsd_scoped_enter_ptr scoped_enter_ptr_t;
	typedef dsd_scoped_enter_ref scoped_enter_ref_t;
#if defined(WIN32) || defined(WIN64)
    inline int m_tryenter() {
       return TryEnterCriticalSection( (CRITICAL_SECTION*)this );
    }
#endif
};

#endif // __HOB__XSLHCLA1_EX__HPP
