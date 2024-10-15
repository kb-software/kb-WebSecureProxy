#=======================================================================#
#                                                                       #
# Makefile for greating the HOBWSPAT2 static library                    #
#   build, rebuild, clean hobwspat2 project                             #
#                                                                       #
# Author                                                                #
# ------                                                                #
#   Michael Jakobs, Mai 2009, HOB GmbH Germany                          #
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
BINTYPE := LIB

#-----------------------------------------------------------------------#
# project name:                                                         #
#-----------------------------------------------------------------------#
PROJECTNAME := hobwspat2


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
OUTDIRADD   := libs/$(PROJECTNAME)


#-----------------------------------------------------------------------#
# output name:                                                          #
#-----------------------------------------------------------------------#
OUTNAME = $(OUTPREFIX)$(PROJECTNAME)$(OUTTYPE)


#-----------------------------------------------------------------------#
# source filelist:                                                      #
#-----------------------------------------------------------------------#
FILES  = $(SRCDIR)/hobwspat.cpp \
         $(SRCDIR)/ds_wspat.cpp \
         $(SRCDIR)/config/ds_at_config.cpp
            
#-----------------------------------------------------------------------#
# resource file (windows only)                                          #
#-----------------------------------------------------------------------#
RESFILE :=


#-----------------------------------------------------------------------#
# include directories:                                                  #
#-----------------------------------------------------------------------#
INCLUDES  = $(INCDIR) \
            $(SOLUTIONDIR)/src/include \
            $(SOLUTIONDIR)/src/lib_sdhstorage/include \
            $(SOLUTIONDIR)/src/lib_wsphelper/include \
            $(SOLUTIONDIR)/src/lib_hobstring/include \
            $(SOLUTIONDIR)/src/lib_authenticate/include \
            $(SOLUTIONDIR)/src/lib_ldap/include \
            $(SOLUTIONDIR)/src/lib_hobvector/include \
            $(SOLUTIONDIR)/src/lib_httpparser/include \
            $(XERCES_SRC) \
            $(SOLUTIONDIR)/$(WSP_INCLUDE)


#-----------------------------------------------------------------------#
# preprocessor defines:                                                 #
#-----------------------------------------------------------------------#
DEFINES := HL_SDH XH_INTERFACE


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

Win_LIBS := kernel32.lib                     # general libraries


# linux settings:
# ---------------
LinGen_CFLAGS := -pthread -fsigned-char -fno-strict-aliasing \
                 -D__HOB_ALIGN__             # general compiler
LinRel_CFLAGS :=                             # release compiler
LinDeb_CFLAGS :=                             # debug   compiler

LinGen_LDFLAGS :=                            # general linker
LinRel_LDFLAGS :=                            # release linker
LinDeb_LDFLAGS :=                            # debug   linker

Lin_LIBS :=                                  # general libraries


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
# include general build file                                            #
#-----------------------------------------------------------------------#
include ../build.mk

