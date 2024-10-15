#=======================================================================#
#                                                                       #
# Makefile for greating the HOBPHONE datahook shared library            #
#   build, rebuild, clean hobphone project                              #
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
PROJECTNAME := sdh_hobphone2


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
OUTDIRADD   := plugins/hobphone
LIBDIRADD   := libs


#-----------------------------------------------------------------------#
# output name:                                                          #
#-----------------------------------------------------------------------#
OUTNAME = xl-sdh-hobphone-01$(OUTTYPE)


#-----------------------------------------------------------------------#
# source filelist:                                                      #
#-----------------------------------------------------------------------#
FILES  = $(SRCDIR)/ds_hobphone2.cpp \
         $(SRCDIR)/sdh_hobphone2.cpp \
         $(SRCDIR)/config/ds_config.cpp

#-----------------------------------------------------------------------#
# resource file (windows only)                                          #
#-----------------------------------------------------------------------#
RESFILE := $(RESDIR)/$(PROJECTNAME).rc


#-----------------------------------------------------------------------#
# include directories:                                                  #
#-----------------------------------------------------------------------#
INCLUDES  = $(INCDIR) \
            $(SRCDIR) \
            $(SOLUTIONDIR)/src/include \
            $(XERCES_SRC) \
            $(SOLUTIONDIR)/src/lib_sdhstorage/include \
            $(SOLUTIONDIR)/src/lib_wsphelper/include \
            $(SOLUTIONDIR)/src/lib_ldap/include \
            $(SOLUTIONDIR)/src/lib_hobstring/include \
            $(SOLUTIONDIR)/src/lib_hashtable/include \
            $(SOLUTIONDIR)/src/lib_hobvector/include \
            $(SOLUTIONDIR)/src/lib_xml/include \
            $(SOLUTIONDIR)/src/lib_xslunic1/include \
            $(SOLUTIONDIR)/src/lib_authenticate/include \
            $(SOLUTIONDIR)/$(WSP_INCLUDE) \
            $(SOLUTIONDIR)/src/lib_wspadmin/include \

#-----------------------------------------------------------------------#
# preprocessor defines:                                                 #
#-----------------------------------------------------------------------#
DEFINES := XH_INTERFACE


#-----------------------------------------------------------------------#
# system depended libaries:                                             #
# taken from $(BINDIRBASE)/$(BTYPE)/$(OS)/$(CPU)/$(LIBDIRADD)           #
#-----------------------------------------------------------------------#
LIBS = wsphelper/$(LIBPREFIX)wsphelper$(LIBTYPE) \
       sdhstorage/$(LIBPREFIX)sdhstorage$(LIBTYPE) \
       ldap/$(LIBPREFIX)ldap$(LIBTYPE) \
       hobstring/$(LIBPREFIX)hobstring$(LIBTYPE) \
       hobvector/$(LIBPREFIX)hobvector$(LIBTYPE) \
       hashtable/$(LIBPREFIX)hashtable$(LIBTYPE) \
       xslunic1/$(LIBPREFIX)xslunic1$(LIBTYPE) \
       authenticate/$(LIBPREFIX)authenticate$(LIBTYPE) \
       wspadmin/$(LIBPREFIX)wspadmin$(LIBTYPE) \
       xml/$(LIBPREFIX)xml$(LIBTYPE)


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
WinRel_CVTFLAGS :=                           # release resource converter
WinDeb_CVTFLAGS :=                           # debug   resource converter

Win_LIBS := wsock32.lib \
            kernel32.lib \
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
LinGen_CFLAGS := -pthread -fsigned-char -fno-strict-aliasing \
                 -D__HOB_ALIGN__ \
                 -D_REENTRANT \
                 -D_THREAD_SAFE \
                 -D_THREAD_SAFE_ERRNO        # general compiler
LinRel_CFLAGS :=                             # release compiler
LinDeb_CFLAGS :=                             # debug   compiler

# -mt 
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

