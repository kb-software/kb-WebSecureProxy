#=======================================================================#
#                                                                       #
# build all Makefile                                                    #
# ------------------                                                    #
#   build, rebuild, all RDVPN-2 projects                                #
#                                                                       #
# Authors                                                               #
# -------                                                               #
#   Michael Jakobs, Okt. 2009, HOB GmbH Germany                         #
#   Michael Fink, since 2015                                            #
#                                                                       #
# Note                                                                  #
# ----                                                                  #
#   This is a GNU make file! Be shure to use gmake on all platforms     #
#                                                                       #
#=======================================================================#


#-----------------------------------------------------------------------#
# build projects:                                                       #
#-----------------------------------------------------------------------#
LIBRARIES := lib_authenticate \
             lib_hashtable \
             lib_hobstring \
             lib_hobvector \
             lib_hobwspat2 \
             lib_ldap \
             lib_resource \
             lib_sdhstorage \
             lib_spnego \
             lib_wspadmin \
             lib_wsphelper \
             lib_xml \
             lib_xslunic1 \
             lib_httpparser

PROJECTS := sdh_compl_check \
            sdh_ea_ldap \
            sdh_hobphone2 \
            sdh_precomp \
            sdh_socks \
            sdh_socks_ftp \
            sdh_trace \
            sdh_webserver \
            xl_sdh_ppp_pf_04 \
            xl-sdh-ppp-pf-05 \
            xl-sdh-ppp-pf-07 \
            xl-sdh-ppp-pf-10 \
            xl-sdh-krb5ts-01 \
            sdh_client_config \
            sdh_gwt_rdp \
            sdh_webterm_te \
            sdh-dash \
            sdh-rdpacc \
            sdh-vnc-bridge

#           wsp

#-----------------------------------------------------------------------#
# analyse platform and set file extensions, directories, etc.           #
#-----------------------------------------------------------------------#

# selected processor:
# -------------------
CPU := invalid
ifeq ($(findstring X86,$(PLATFORM)),X86)
    CPU:=x86
endif
ifeq ($(findstring X64,$(PLATFORM)),X64)
    CPU:=em64t
endif
ifeq ($(findstring IPF,$(PLATFORM)),IPF)
    CPU:=ipf
endif
ifeq ($(findstring Sparc64,$(PLATFORM)),Sparc64)
    CPU:=sparc64
endif
ifeq ($(findstring PARISC,$(PLATFORM)),PARISC)
    CPU:=parisc
endif
ifeq ($(findstring PPC,$(PLATFORM)),PPC)
    CPU:=ppc
endif

# selected os:
# ------------
OS := invalid
ifeq ($(findstring Win,$(PLATFORM)),Win)
    OS:=windows
endif

ifeq ($(findstring Lin,$(PLATFORM)),Lin)
    OS:=linux
endif

ifeq ($(findstring Sol,$(PLATFORM)),Sol)
    OS:=solaris
endif

ifeq ($(findstring Hpux,$(PLATFORM)),Hpux)
    OS:=hpux
endif

ifeq ($(findstring Aix,$(PLATFORM)),Aix)
    OS:=aix
endif

ifeq ($(findstring Bsd,$(PLATFORM)),Bsd)
    OS:=freebsd
endif


#-----------------------------------------------------------------------#
# check if all variables are valid:                                     #
#-----------------------------------------------------------------------#
ifneq ($(MAKECMDGOALS),HELP)
    ifeq ($(PLATFORM),)
            $(error PLATFORM undefined, try "gmake HELP")
    endif
    ifeq ($(findstring invalid,$(OS)),invalid)
        $(error no valid OS in PLATFORM, try "gmake HELP")
    endif
    ifeq ($(findstring invalid,$(CPU)),invalid)
        $(error no valid CPU in PLATFORM, try "gmake HELP")
    endif
endif



#-----------------------------------------------------------------------#
# make rules:                                                           #
#-----------------------------------------------------------------------#

.PHONY: all clean rebuild
all clean rebuild: $(PROJECTS)

.PHONY: $(PROJECTS) $(LIBRARIES)

$(PROJECTS): $(LIBRARIES)

$(PROJECTS) $(LIBRARIES):
	$(MAKE) --directory=$@ PLATFORM=${PLATFORM} $(MAKECMDGOALS)


.PHONY: HELP
HELP:
	$(m_help)

#-----------------------------------------------------------------------#
# macro definitions:                                                    #
#-----------------------------------------------------------------------#

#
# $(call m_print,string)
#
# print outputs
#
define m_print
    @echo $1
endef

#
# $(m_help)
#
# print a help text
#
define m_help
    $(call m_print,Makefile for building all RDVPN-2 projects )
    $(call m_print,                                           )
    $(call m_print,usage: gmake PLATFORM=PF [clean rebuild]   )
    $(call m_print,                                           )
    $(call m_print,where PF can be:                           )
    $(call m_print,                                           )
    $(call m_print,    for Windows builds:                    )
    $(call m_print,    -------------------                    )
    $(call m_print,        WinX86 WinX64 WinIPF  [+dbg ins]   )
    $(call m_print,                                           )
    $(call m_print,    for Linux builds:                      )
    $(call m_print,    -----------------                      )
    $(call m_print,        LinX86 LinX64 LinIPF  [+dbg]       )
    $(call m_print,                                           )
    $(call m_print,    for FreeBSD builds:                    )
    $(call m_print,    -------------------                    )
    $(call m_print,        BsdX64  [+dbg]                     )
    $(call m_print,                                           )
    $(call m_print,    for Solaris builds:                    )
    $(call m_print,    -------------------                    )
    $(call m_print,        SolX64 SolSparc64  [+dbg]          )
    $(call m_print,                                           )
    $(call m_print,    for HPUX builds:                       )
    $(call m_print,    ----------------                       )
    $(call m_print,        HpuxPARISC HpuxIPF  [+dbg]         )
    $(call m_print,                                           )
    $(call m_print,    for AIX builds:                        )
    $(call m_print,    ---------------                        )
    $(call m_print,        AixPPC  [+dbg]                     )
    $(call m_print,                                           )
    $(call m_print,                                           )
    $(call m_print,Notes:                                     )
    $(call m_print,------                                     )
    $(call m_print,  Append "dbg" for debug - like WinX64dbg  )
    $(call m_print,  or "ins" for insure - Windows only       )
    $(call m_print,                                           )
    $(call m_print,  On the Windows Platform the VisualStudio )
    $(call m_print,  installation directory has to be         )
    $(call m_print,  provided in the variable VSINSTALLDIR.   )
endef
