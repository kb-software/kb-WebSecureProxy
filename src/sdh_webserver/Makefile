#=======================================================================#
#                                                                       #
# Makefile for greating the WEBSERVER datahook shared library           #
#   build, rebuild, clean webserver project                             #
#                                                                       #
# Author                                                                #
# ------                                                                #
#   Michael Jakobs, April 2009, HOB GmbH Germany                        #
#                                                                       #
# Note                                                                  #
# ----                                                                  #
#   This is a GNU make file! Be shure to use gmake on all platforms     #
#                                                                       #
# Needed Macros                                                         #
# -------------                                                         #
#   VSINSTALLDIR     - VisualStudio Installation Directory              #
#                      (Windows only)                                   #
#                                                                       #
#=======================================================================#


#-----------------------------------------------------------------------#
# binary build type:                                                    #
#-----------------------------------------------------------------------#
BINTYPE := DLL

#-----------------------------------------------------------------------#
# project name:                                                         #
#-----------------------------------------------------------------------#
PROJECTNAME := wsp_webserver


#-----------------------------------------------------------------------#
# general directories:                                                  #
#-----------------------------------------------------------------------#
PROJECTDIR  := .
SOLUTIONDIR := $(PROJECTDIR)/../..
SRCDIR      := $(PROJECTDIR)/src
INCDIR      := $(PROJECTDIR)/include
RESDIR      := $(PROJECTDIR)/res
BINDIRBASE  := $(SOLUTIONDIR)/bin
OBJDIRBASE  := $(SOLUTIONDIR)/obj
OUTDIRADD   := plugins/web_server
LIBDIRADD   := libs


#-----------------------------------------------------------------------#
# output name:                                                          #
#-----------------------------------------------------------------------#
OUTNAME = xl-sdh-webserver-01$(OUTTYPE)


#-----------------------------------------------------------------------#
# source filelist:                                                      #
#-----------------------------------------------------------------------#
FILES  = $(SRCDIR)/ds_control.cpp\
         $(SRCDIR)/ds_datablock.cpp\
         $(SRCDIR)/ds_http_header.cpp\
         $(SRCDIR)/ds_id.cpp\
         $(SRCDIR)/ds_page.cpp\
         $(SRCDIR)/ds_session.cpp\
         $(SRCDIR)/ds_state.cpp\
         $(SRCDIR)/ds_transaction.cpp\
         $(SRCDIR)/ds_url.cpp\
         $(SRCDIR)/ds_url_parser.cpp\
         $(SRCDIR)/ds_zlib.cpp\
         $(SRCDIR)/sdh_web_server.cpp\
         $(SRCDIR)/xszlib01.cpp\
         $(SRCDIR)/iws/ds_webserver.cpp\
         $(SRCDIR)/wsg/ds_ws_gate.cpp\
         $(SRCDIR)/wsg/interpreter/ds_attributes.cpp\
         $(SRCDIR)/wsg/interpreter/ds_interpret.cpp\
         $(SRCDIR)/wsg/interpreter/ds_interpret_css.cpp\
         $(SRCDIR)/wsg/interpreter/ds_interpret_html.cpp\
         $(SRCDIR)/wsg/interpreter/ds_interpret_script.cpp\
         $(SRCDIR)/wsg/interpreter/dsd_interpret_ica.cpp\
         $(SRCDIR)/wsg/interpreter/ds_interpret_xml.cpp\
         $(SRCDIR)/wsg/interpreter/ds_scriptvariables.cpp\
         $(SRCDIR)/spnego/ds_spnego_reader.cpp\
         $(SRCDIR)/utils/helper.cpp\
         $(SRCDIR)/portal/ds_xsl.cpp\
         $(SRCDIR)/portal/ds_parse_xsl.cpp\
         $(SRCDIR)/login/ds_pre_cma.cpp\
         $(SRCDIR)/login/ds_auth.cpp\
         $(SRCDIR)/config/ds_ppp_tunnel.cpp\
         $(SRCDIR)/config/ds_virtual_link.cpp\
         $(SRCDIR)/authlib/xs-wspat-entry.cpp\
         $(SRCDIR)/auth_callback.cpp\
         $(SOLUTIONDIR)/$(WSP_SRC)/xs-encry-1.cpp \
         $(SRCDIR)/utils/xs_user_agent_worker.cpp

#-----------------------------------------------------------------------#
# include assembler sources of SSL Library                              #
#-----------------------------------------------------------------------#
include ../files_ssl.mk

#-----------------------------------------------------------------------#
# resource file (windows only)                                          #
#-----------------------------------------------------------------------#
RESFILE := $(RESDIR)/sdh_webserver.rc


#-----------------------------------------------------------------------#
# include directories:                                                  #
#-----------------------------------------------------------------------#
INCLUDES  = $(INCDIR) \
            $(SOLUTIONDIR)/src/include \
            $(XERCES_SRC) \
            $(SOLUTIONDIR)/src/lib_sdhstorage/include \
            $(SOLUTIONDIR)/src/lib_wsphelper/include \
            $(SOLUTIONDIR)/src/lib_ldap/include \
            $(SOLUTIONDIR)/src/lib_spnego/include \
            $(SOLUTIONDIR)/src/lib_hobstring/include \
            $(SOLUTIONDIR)/src/lib_hobvector/include \
            $(SOLUTIONDIR)/src/lib_wspadmin/include \
            $(SOLUTIONDIR)/src/lib_hashtable/include \
            $(SOLUTIONDIR)/src/lib_xslunic1/include \
            $(SOLUTIONDIR)/src/lib_xml/include \
            $(SOLUTIONDIR)/src/lib_hobwspat2/include \
            $(SOLUTIONDIR)/src/lib_authenticate/include \
            $(SOLUTIONDIR)/src/lib_resource/include \
            $(SOLUTIONDIR)/src/lib_httpparser/include \
            $(SOLUTIONDIR)/$(WSP_INCLUDE)


#-----------------------------------------------------------------------#
# preprocessor defines:                                                 #
#-----------------------------------------------------------------------#
DEFINES := DS_PORTLET_FILTER_U_A \
           XH_INTERFACE \
           USE_ASSEMBLER_SOURCES \
           HOB_WIN64_ASM=0 \
           BO_HOBTE_CONFIG=1


#-----------------------------------------------------------------------#
# system depended libaries:                                             #
# taken from $(BINDIRBASE)/$(BTYPE)/$(OS)/$(CPU)/$(LIBDIRADD)           #
#-----------------------------------------------------------------------#
LIBS = wsphelper/$(LIBPREFIX)wsphelper$(LIBTYPE) \
       sdhstorage/$(LIBPREFIX)sdhstorage$(LIBTYPE) \
       spnego/$(LIBPREFIX)spnego$(LIBTYPE) \
       hobstring/$(LIBPREFIX)hobstring$(LIBTYPE) \
       hobvector/$(LIBPREFIX)hobvector$(LIBTYPE) \
       wspadmin/$(LIBPREFIX)wspadmin$(LIBTYPE) \
       xslunic1/$(LIBPREFIX)xslunic1$(LIBTYPE) \
       hobwspat2/$(LIBPREFIX)hobwspat2$(LIBTYPE) \
       authenticate/$(LIBPREFIX)authenticate$(LIBTYPE) \
       resource/$(LIBPREFIX)resource$(LIBTYPE) \
       httpparser/$(LIBPREFIX)httpparser$(LIBTYPE) \
       xml/$(LIBPREFIX)xml$(LIBTYPE) \
       ldap/$(LIBPREFIX)ldap$(LIBTYPE)


#-----------------------------------------------------------------------#
# special settings for each system:                                     #
#-----------------------------------------------------------------------#

# windows settings:
# -----------------
WinGen_CFLAGS :=                             # general compiler 
WinRel_CFLAGS :=                             # release compiler
WinDeb_CFLAGS :=                             # debug   compiler

WinGen_LDFLAGS :=                            # general linker
WinRel_LDFLAGS :=                            # release linker
WinDeb_LDFLAGS :=                            # debug   linker

WinGen_RCFLAGS :=                            # general resource compiler
WinRel_RCFLAGS :=                            # release resource compiler
WinDeb_RCFLAGS :=                            # debug   resource compiler

WinGen_CVTFLAGS :=                           # general resource converter
WinRel_CVTFLAGS :=		                     # release resource converter
WinDeb_CVTFLAGS :=                           # debug   resource converter

Win_LIBS := kernel32.lib \
            user32.lib \
            gdi32.lib \
            winspool.lib \
            comdlg32.lib \
            advapi32.lib \
            shell32.lib \
            ole32.lib \
            oleaut32.lib \
            uuid.lib \
            odbc32.lib \
            odbccp32.lib                     # general libraries
            

# linux settings:
# ---------------
LinGen_CFLAGS := -fno-strict-aliasing -pthread -fsigned-char \
                 -D__HOB_ALIGN__ \
                 -D_REENTRANT \
                 -D_THREAD_SAFE \
                 -D_THREAD_SAFE_ERRNO        # general compiler
LinRel_CFLAGS :=                             # release compiler
LinDeb_CFLAGS :=                             # debug   compiler

LinGen_LDFLAGS := -pthread               # general linker
LinRel_LDFLAGS :=                            # release linker
LinDeb_LDFLAGS :=                            # debug   linker

Lin_LIBS := -lstdc++ -lnsl -ldl -lpthread    # general libraries


# solaris settings:
# -----------------
SolGen_CFLAGS := -mt -errtags=yes \
				 -erroff=wbadasg,badargtype2w,badargtypel2w,badargtypelw,wbadasgl,wbadinitl,truncwarn \
                 -D__HOB_ALIGN__ \
                 -D_REENTRANT \
                 -D_THREAD_SAFE \
                 -D_THREAD_SAFE_ERRNO        # general compiler
SolRel_CFLAGS :=                             # release compiler
SolDeb_CFLAGS :=                             # debug   compiler

SolGen_LDFLAGS := -mt                        # general linker
SolRel_LDFLAGS :=                            # release linker
SolDeb_LDFLAGS :=                            # debug   linker

Sol_LIBS := -lnsl -ldl -lpthread             # general libraries


# hpux settings:
# --------------
HpuxGen_CFLAGS :=                            # general compiler
HpuxRel_CFLAGS :=                            # release compiler
HpuxDeb_CFLAGS :=                            # debug   compiler

HpuxGen_LDFLAGS :=                           # general linker
HpuxRel_LDFLAGS :=                           # release linker
HpuxDeb_LDFLAGS :=                           # debug   linker

Hpux_LIBS :=                                 # general libraries


# aix settings:
# -------------
AixGen_CFLAGS :=                             # general compiler
AixRel_CFLAGS :=                             # release compiler
AixDeb_CFLAGS :=                             # debug   compiler

AixGen_LDFLAGS :=                            # general linker
AixRel_LDFLAGS :=                            # release linker
AixDeb_LDFLAGS :=                            # debug   linker

Aix_LIBS :=                                  # general libraries


#-----------------------------------------------------------------------#
# pre build jobs for each system:                                       #
#-----------------------------------------------------------------------#
WinPreBuild := $(PROJECTDIR)/create-resource.bat
LinPreBuild :=
SolPreBuild :=
HpuxPreBuild :=
AixPreBuild :=


#-----------------------------------------------------------------------#
# include general build file                                            #
#-----------------------------------------------------------------------#
include ../build.mk

