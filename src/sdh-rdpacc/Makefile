#=======================================================================#
#                                                                       #
# Makefile for creating the RDP-ACC Virus Checking SDH shared library   #
#   build, rebuild and clean project                                    #
#                                                                       #
# Author                                                                #
# ------                                                                #
#   David Davila, HOB GmbH Germany - 2015                               #
#   Based on previous one by Tobias Hoffman                             #
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
PROJECTNAME := sdh-rdpacc


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
OUTDIRADD   := plugins/rdpacc
LIBDIRADD   := libs


#-----------------------------------------------------------------------#
# output name:                                                          #
#-----------------------------------------------------------------------#
OUTNAME = xlrdphovch1$(OUTTYPE)


#-----------------------------------------------------------------------#
# source filelist:                                                      #
#-----------------------------------------------------------------------#
FILES  = $(SOLUTIONDIR)/$(WSP_SRC)/xs-encry-1.cpp \
		 $(SRCDIR)/xs-cdr-mppc-4.cpp \
		 $(SRCDIR)/xs-cdr-mppc-5.cpp \
		 $(SRCDIR)/xsl-stor-sdh-big.cpp \
		 $(SRCDIR)/xsrdptracer1.cpp  \
		 $(SRCDIR)/xsrdpvch1.cpp  \
		 $(SRCDIR)/xlrdpho1.cpp

#-----------------------------------------------------------------------#
# include assembler sources of SSL Library                              #
#-----------------------------------------------------------------------#
include ../files_ssl.mk

#-----------------------------------------------------------------------#
# resource file (windows only)                                          #
#-----------------------------------------------------------------------#
RESFILE := $(RESDIR)/$(PROJECTNAME).rc

#-----------------------------------------------------------------------#
# include directories:                                                  #
#-----------------------------------------------------------------------#
INCLUDES  = $(INCDIR) \
            $(SOLUTIONDIR)/src/include \
            $(XERCES_SRC) \
            $(SOLUTIONDIR)/$(WSP_INCLUDE)

#-----------------------------------------------------------------------#
# preprocessor defines:                                                 #
#-----------------------------------------------------------------------#
DEFINES := HL_COMP_MULTI \
           HCOMPR2 \
           NEW_WSP_1102 \
           XLRDPHOVCH1_EXPORTS \
           XH_INTERFACE \
           USE_ASSEMBLER_SOURCES \
           HOB_WIN64_ASM=0

#-----------------------------------------------------------------------#
# system depended libaries:                                             #
# taken from $(BINDIRBASE)/$(BTYPE)/$(OS)/$(CPU)/$(LIBDIRADD)           #
#-----------------------------------------------------------------------#
LIBS = xslunic1/$(LIBPREFIX)xslunic1$(LIBTYPE) 
#       sdhstorage/$(LIBPREFIX)sdhstorage$(LIBTYPE)

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
            psapi.lib \
            Iphlpapi.lib \
            ole32.lib \
            oleaut32.lib \
            uuid.lib \
            odbc32.lib \
            odbccp32.lib                     # general libraries
            

# linux settings:
# ---------------
LinGen_CFLAGS := -fno-strict-aliasing -pthread -fsigned-char \
                 -Wno-write-strings \
                 -fPIC -lpthread \
                 -D__HOB_ALIGN__ \
                 -D_REENTRANT \
                 -D_THREAD_SAFE \
                 -D_THREAD_SAFE_ERRNO        # general compiler
LinRel_CFLAGS :=                             # release compiler
LinDeb_CFLAGS :=                             # debug   compiler

LinGen_LDFLAGS := -pthread                   # general linker
LinRel_LDFLAGS :=                            # release linker
LinDeb_LDFLAGS :=                            # debug   linker

Lin_LIBS := -lstdc++ -lnsl -ldl -lpthread    # general libraries


# solaris settings:
# -----------------
SolGen_CFLAGS :=                             # general compiler
SolRel_CFLAGS :=                             # release compiler
SolDeb_CFLAGS :=                             # debug   compiler

SolGen_LDFLAGS :=                            # general linker
SolRel_LDFLAGS :=                            # release linker
SolDeb_LDFLAGS :=                            # debug   linker

Sol_LIBS :=                                  # general libraries


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

