#=======================================================================#
#                                                                       #
# general build Makefile                                                #
# ----------------------                                                #
#   build, rebuild, clean every C/C++ project                           #
#                                                                       #
# Authors                                                               #
# -------                                                               #
#   Michael Jakobs, April 2009, HOB GmbH Germany                        #
#   Michael Fink, since 2015                                            #
#                                                                       #
#                                                                       #
# Note                                                                  #
# ----                                                                  #
#   This is a GNU make file! Be sure to use gmake on all platforms      #
#   For make, SPACES and TABS are not the same!                         #
#   Make sure that your editor DOes NOT REPLACE TABS WITH SPACES        #
#                              ==   ============================        #
#                                                                       #
# Needed Macros                                                         #
# -------------                                                         #
#   BINTYPE          - type of binary (posible: EXE,DLL,LIB)            #
#                                                                       #
#   PROJECTNAME      - name of project                                  #
#                                                                       #
#   OUTNAME          - target output filename                           #
#   BINDIRBASE       - output directory for binaries                    #
#                      (some platform path and OUTDIRADD will be added) #
#   OBJDIRBASE       - output directory for objects                     #
#                      (some platform path and OUTDIRADD will be added) #
#   OUTDIRADD        - additional output directory path                 #
#                                                                       #
#   FILES            - list of source files (*.c and *.cpp)             #
#   INCLUDES         - list of include directories                      #
#   DEFINES          - preprocessor defines                             #
#                      (_DEBUG and NDEBUG is set automatic)             #
#                                                                       #
#   RESFILE          - resource file (windows only)                     #
#   RESDIR           - directory of resource file                       #
#                                                                       #
#=======================================================================#


#-----------------------------------------------------------------------#
# global defines                                                        #
#-----------------------------------------------------------------------#
DEFINES += NOT_KB_DIRECT
DEFINES += HOB_WSG_DEVELOPMENT=0

#-----------------------------------------------------------------------#
# give debug outputs for make process?                                  #
#-----------------------------------------------------------------------#
#DEBUG := 1

#-----------------------------------------------------------------------#
# pre-define WSP directories (relative to SOLUTIONDIR := wsp-sdhs)      #
#-----------------------------------------------------------------------#

# These WSP source directories can be over-written to build SDHs for
# different WSP sources, e.g.:

#   gmake PLATFORM=WinX64 WSP_INCLUDE=../wsp-archive/wsp23scs \
#                         WSP_SRC=../wsp-archive/wsp23scs
WSP_SRC := src/wsp
WSP_INCLUDE := src/wsp

#-----------------------------------------------------------------------#
# analyse platform and set file extensions, directories, etc.           #
#-----------------------------------------------------------------------#

# selected buildtype:
# -------------------
ifeq ($(findstring dbg,$(PLATFORM)),dbg)
	BTYPE:=debug
else
	ifeq ($(findstring ins,$(PLATFORM)),ins)
		BTYPE:=insure
	else
		BTYPE:=release
	endif
endif

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
	
	# windows library type:
	LIBTYPE=.lib

    # windows file extensions:
    OBJTYPE=.obj
    ifeq ($(BINTYPE),EXE)
        OUTTYPE=.exe
    endif
    ifeq ($(BINTYPE),DLL)
        OUTTYPE=.dll
    endif
    ifeq ($(BINTYPE),LIB)
        OUTTYPE=.lib
    endif
    
    # get header files shell command
    GETHDR:=dir /B $(subst /,\,$(addsuffix /*.h,$(INCLUDES))) $(subst /,\,$(addsuffix /*.hpp,$(INCLUDES))) $(subst /,\,$(addsuffix /*.h,$(SRCDIR))) $(subst /,\,$(addsuffix /*.hpp,$(SRCDIR))) 2>nul

    # check if VisualStudio Installdirectory is set:
    ifeq ($(VSINSTALLDIR),)
        $(error No VisualStudio Installdirectory specified, try "gmake HELP")
    endif

    OBJECTS_SO_CPP=$(subst .cpp,$(OBJTYPE),$(filter %.cpp,$(WinFiles)))
    OBJECTS_SO_C  =$(subst .c,$(OBJTYPE),$(filter %.c,$(WinFiles)))
endif

ifeq ($(findstring Lin,$(PLATFORM)),Lin)
	OS:=linux
	
	# linux library type:
	LIBPREFIX=lib
	LIBTYPE=.a

    # linux file extensions:
    OBJTYPE=.o
    ifeq ($(BINTYPE),EXE)
        OUTTYPE=
	    OUTPREFIX=
    endif
    ifeq ($(BINTYPE),DLL)
        OUTTYPE=.so
	    OUTPREFIX=lib
    endif
    ifeq ($(BINTYPE),LIB)
        OUTTYPE=.a
	    OUTPREFIX=lib
    endif
    
    # get header files shell command
    GETHDR:=find $(INCLUDES) $(SRCDIR) -iname *.h -or -iname *.hpp 2>/dev/null

    OBJECTS_SO_CPP=$(subst .cpp,$(OBJTYPE),$(filter %.cpp,$(UnixFiles)))
    OBJECTS_SO_C  =$(subst .c,$(OBJTYPE),$(filter %.c,$(UnixFiles)))
endif

ifeq ($(findstring Sol,$(PLATFORM)),Sol)
	OS:=solaris

    # solaris file extensions:
    OBJTYPE=.o
	ifeq ($(BINTYPE),EXE)
        OUTTYPE=
	    OUTPREFIX=
    endif
    ifeq ($(BINTYPE),DLL)
        OUTTYPE=.so
	    OUTPREFIX=lib
    endif
    
    # get header files shell command
    GETHDR:=find $(INCLUDES) $(SRCDIR) -iname *.h -or -iname *.hpp 2>/dev/null

    OBJECTS_SO_CPP=$(subst .cpp,$(OBJTYPE),$(filter %.cpp,$(UnixFiles)))
    OBJECTS_SO_C  =$(subst .c,$(OBJTYPE),$(filter %.c,$(UnixFiles)))
endif

ifeq ($(findstring Hpux,$(PLATFORM)),Hpux)
	OS:=hpux

    # HPUX file extensions:
    OBJTYPE=.o
	ifeq ($(findstring PARISC,$(PLATFORM)),PARISC)
    	ifeq ($(BINTYPE),EXE)
            OUTTYPE=
	        OUTPREFIX=
        endif
        ifeq ($(BINTYPE),DLL)
            OUTTYPE=.sl
	        OUTPREFIX=lib
        endif
	else
    	ifeq ($(BINTYPE),EXE)
            OUTTYPE=
	        OUTPREFIX=
        endif
        ifeq ($(BINTYPE),DLL)
            OUTTYPE=.so
	        OUTPREFIX=lib
        endif
	endif
    
    # get header files shell command
    GETHDR:=find $(INCLUDES) $(SRCDIR) -iname *.h -or -iname *.hpp 2>/dev/null

    OBJECTS_SO_CPP=$(subst .cpp,$(OBJTYPE),$(filter %.cpp,$(UnixFiles)))
    OBJECTS_SO_C  =$(subst .c,$(OBJTYPE),$(filter %.c,$(UnixFiles)))
endif

ifeq ($(findstring Aix,$(PLATFORM)),Aix)
	OS:=aix

    # AIX file extensions:
    OBJTYPE=.o
	ifeq ($(BINTYPE),EXE)
        OUTTYPE=
	    OUTPREFIX=
    endif
    ifeq ($(BINTYPE),DLL)
        OUTTYPE=.sl
	    OUTPREFIX=lib
    endif
    
    # get header files shell command
    GETHDR:=find $(INCLUDES) $(SRCDIR) -iname *.h -or -iname *.hpp 2>/dev/null

    OBJECTS_SO_CPP=$(subst .cpp,$(OBJTYPE),$(filter %.cpp,$(UnixFiles)))
    OBJECTS_SO_C  =$(subst .c,$(OBJTYPE),$(filter %.c,$(UnixFiles)))
endif

ifeq ($(findstring Bsd,$(PLATFORM)),Bsd)
	OS:=freebsd
	
	# freebsd library type:
	LIBPREFIX=lib
	LIBTYPE=.a

    # linux file extensions:
    OBJTYPE=.o
    ifeq ($(BINTYPE),EXE)
        OUTTYPE=
	    OUTPREFIX=
    endif
    ifeq ($(BINTYPE),DLL)
        OUTTYPE=.so
	    OUTPREFIX=lib
    endif
    ifeq ($(BINTYPE),LIB)
        OUTTYPE=.a
	    OUTPREFIX=lib
    endif
    
    # get header files shell command
    GETHDR:=find $(INCLUDES) $(SRCDIR) -iname *.h -or -iname *.hpp 2>/dev/null

    OBJECTS_SO_CPP=$(subst .cpp,$(OBJTYPE),$(filter %.cpp,$(UnixFiles)))
    OBJECTS_SO_C  =$(subst .c,$(OBJTYPE),$(filter %.c,$(UnixFiles)))
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
# output directories:                                                   #
#-----------------------------------------------------------------------#
BINDIR=$(BINDIRBASE)/$(BTYPE)/$(OS)/$(CPU)/$(OUTDIRADD)
ifdef OUTDIRADD_OBJ
OBJDIR=$(OBJDIRBASE)/$(BTYPE)/$(OS)/$(CPU)/$(OUTDIRADD_OBJ)
else
OBJDIR=$(OBJDIRBASE)/$(BTYPE)/$(OS)/$(CPU)/$(OUTDIRADD)
endif
vpath %$(OUTTYPE) $(BINDIR)
vpath %$(OBJTYPE) $(OBJDIR)


#-----------------------------------------------------------------------#
# object file list:                                                     #
#-----------------------------------------------------------------------#
OBJECTS_CPP= $(addprefix $(OBJDIR)/,$(subst .cpp,$(OBJTYPE),$(filter %.cpp,$(FILES))))
OBJECTS_C  = $(addprefix $(OBJDIR)/,$(subst .c,$(OBJTYPE),$(filter %.c,$(FILES))))
OBJECTS_ASM= $(addprefix $(OBJDIR)/,$(subst .asm,$(OBJTYPE),$(filter %.asm,$(FILES))))
OBJECTS_S  = $(addprefix $(OBJDIR)/,$(subst .s,$(OBJTYPE),$(filter %.s,$(FILES))))
OBJECTS    = $(OBJECTS_CPP) $(OBJECTS_C) $(OBJECTS_SO_CPP) $(OBJECTS_SO_C) \
             $(OBJECTS_ASM) $(OBJECTS_S)


#-----------------------------------------------------------------------#
# header file list:                                                     #
#-----------------------------------------------------------------------#
vpath %.h   $(INCLUDES) $(SRCDIR)
vpath %.H   $(INCLUDES) $(SRCDIR)
vpath %.hpp $(INCLUDES) $(SRCDIR)
HEADERS:=$(shell $(GETHDR))



#-----------------------------------------------------------------------#
# make rules:                                                           #
#-----------------------------------------------------------------------#
OUTNAME := $(BINDIR)/$(OUTNAME)

#-----------------------------------------------------------------------#
# link rule:                                                            #
#-----------------------------------------------------------------------#
$(OUTNAME): $(addprefix $(BINDIRBASE)/$(BTYPE)/$(OS)/$(CPU)/$(LIBDIRADD)/,$(LIBS))
$(OUTNAME): $(OBJECTS)
	$(m_comp_res)
	$(m_link)
	$(m_embed_manifest)


.PHONY: HELP
HELP:
	$(m_help)


.PHONY: clean
clean:
	$(m_cleanup)


.PHONY: rebuild
rebuild: clean $(OUTNAME)


#-----------------------------------------------------------------------#
# build rule for the object files:                                      #
#-----------------------------------------------------------------------#
$(OBJECTS): $(HEADERS)

$(OBJECTS_CPP): $(OBJDIR)/%$(OBJTYPE): %.cpp
	$(m_compile)

$(OBJECTS_C): $(OBJDIR)/%$(OBJTYPE): %.c
	$(m_compile)

$(OBJECTS_SO_CPP): $(OBJDIR)/%$(OBJTYPE): %.cpp
	$(m_compile)

$(OBJECTS_SO_C): $(OBJDIR)/%$(OBJTYPE): %.c
	$(m_compile)

$(OBJECTS_ASM): $(OBJDIR)/%$(OBJTYPE): %.asm
	$(m_compile_asm)

$(OBJECTS_S): $(OBJDIR)/%$(OBJTYPE): %.s
	$(m_compile_s)


#-----------------------------------------------------------------------#
# macro definitions:                                                    #
#-----------------------------------------------------------------------#

#
# $(m_setup)
#
# m_setup compiler and linker depending on calling platform
#
define m_setup
    $(call m_print,$(PROJECTNAME) $(BTYPE) $(BINTYPE) for $(OS) $(CPU) selected)
	
	$(m_add_project_incl)
	    
    $(if $(filter $(BTYPE),debug),
		$(eval CFLAGS:=-D_DEBUG)
	)
	$(if $(filter $(BTYPE),release),
		$(eval CFLAGS:=-DNDEBUG)
	)
	$(if $(filter $(BTYPE),insure),
		$(eval CFLAGS:=-D_DEBUG)
	)


	$(if $(filter $(OS),windows),
		$(m_setup_windows)
	)
	$(if $(filter $(OS),linux),
		$(m_setup_linux)
	)
	$(if $(filter $(OS),solaris),
		$(m_setup_solaris)
	)
	$(if $(filter $(OS),hpux),
		$(m_setup_hpux)
	)
	$(if $(filter $(OS),aix),
		$(m_setup_aix)
	)
	$(if $(filter $(OS),freebsd),
		$(m_setup_freebsd)
	)
	
	$(m_setting_overview)   
    $(m_prebuild_events)
endef

#
# $(m_prebuild_events)
#
# handle given prebuild event for each system
#
define m_prebuild_events
	$(if $(filter $(OS),windows),
		$(if $(WinPreBuild),
			$(shell "$(WinPreBuild)")
		)
	)
	$(if $(filter $(OS),linux),
		$(if $(LinPreBuild),
			$(shell "$(LinPreBuild)")
		)
	)
	$(if $(filter $(OS),solaris),
		$(if $(SolPreBuild),
			$(shell "$(SolPreBuild)")
		)
	)
	$(if $(filter $(OS),hpux),
		$(if $(HpuxPreBuild),
			$(shell "$(HpuxPreBuild)")
		)
	)
	$(if $(filter $(OS),aix),
		$(if $(AixPreBuild),
			$(shell "$(AixPreBuild)")
		)
	)
	$(if $(filter $(OS),freebsd),
		$(if $(BsdPreBuild),
			$(shell "$(BsdPreBuild)")
		)
	)
endef


#
# $(m_add_project_incl)
# 
# add project includes to CINC variable
#
define m_add_project_incl
	$(foreach ADD,$(INCLUDES),
	    $(eval CINC:=$(CINC) -I'$(ADD)')
    )
endef


#
# $(m_setup_windows)
#
# setup windows compiler and linker settings
# depending on selected target
#
# -wd4310 
define m_setup_windows
    $(foreach ADD,$(VSINSTALLDIR),
	    $(eval VS_PATH+=$(subst \,/,$(ADD)))
	)

    $(eval VCLIB:=$(VS_PATH)/VC/Lib)
    $(eval SDKLIB:=$(VS_PATH)/VC/PlatformSDK/Lib)

    $(eval WinRel_CFLAGS:=-O2 -MT -Zi /analyze /we6284 /we6067 /we6271 $(WinRel_CFLAGS))
    $(eval WinDeb_CFLAGS:=-Od -MTd -RTC1 -Zi /analyze /we6284 /we6067 /we6271 $(WinDeb_CFLAGS))
    $(if $(filter $(BINTYPE),LIB),
        ,
        $(eval WinRel_LDFLAGS:=-DEBUG -OPT:REF -OPT:ICF $(WinRel_LDFLAGS))
    )

	$(if $(filter $(CPU),x86),
	    $(eval VCBIN:=$(VS_PATH)/VC/bin)
        $(eval CFLAGS   += -DHL_PRFMAXSO_I=4 -DHL_PRFMAXSO_L=4 -DHL_PRFMAXSO_LL=8)

		$(if $(filter $(BTYPE),release),
	    	$(eval CFLAGS   += -DWIN32\
                               $(WinGen_CFLAGS) $(WinRel_CFLAGS))
	    	$(eval LDFLAGS  := -MACHINE:X86\
                               $(WinGen_LDFLAGS) $(WinRel_LDFLAGS)\
						       -LIBPATH:'$(VCLIB)';'$(SDKLIB)'     )
	    	$(eval RCFLAGS  := -DWIN32 -DNDEBUG\
                               $(WinGen_RCFLAGS) $(WinRel_RCFLAGS))
	    	$(eval CVTFLAGS := -NOLOGO -MACHINE:X86\
                               $(WinGen_CVTFLAGS) $(WinRel_CVTFLAGS))
		)

		$(if $(filter $(BTYPE),debug),
	    	$(eval CFLAGS   += -DWIN32\
                               $(WinGen_CFLAGS) $(WinDeb_CFLAGS))
            $(if $(filter $(BINTYPE),LIB),
	    	    $(eval LDFLAGS  := -MACHINE:X86\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)';'$(SDKLIB)'     )
            ,
	    	    $(eval LDFLAGS  := -MACHINE:X86 -DEBUG\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)';'$(SDKLIB)'     )
            )
	    	$(eval RCFLAGS  := -DWIN32 -D_DEBUG\
                               $(WinGen_RCFLAGS) $(WinDeb_RCFLAGS))
	    	$(eval CVTFLAGS := -NOLOGO -MACHINE:X86\
                               $(WinGen_CVTFLAGS) $(WinDeb_CVTFLAGS))
		)
		$(if $(filter $(BTYPE),insure),
	    	$(eval CFLAGS   += -DWIN32\
                               $(WinGen_CFLAGS) $(WinDeb_CFLAGS))
            $(if $(filter $(BINTYPE),LIB),
	    	    $(eval LDFLAGS  := -MACHINE:X86\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)';'$(SDKLIB)'     )
            ,
	    	    $(eval LDFLAGS  := -MACHINE:X86 -DEBUG\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)';'$(SDKLIB)'     )
            )
	    	$(eval RCFLAGS  := -DWIN32 -D_DEBUG\
                               $(WinGen_RCFLAGS) $(WinDeb_RCFLAGS))
	    	$(eval CVTFLAGS := -NOLOGO -MACHINE:X86\
                               $(WinGen_CVTFLAGS) $(WinDeb_CVTFLAGS))
		)

		$(eval MASM:=$(VCBIN)/ml)
	)

	$(if $(filter $(CPU),em64t),
	    $(eval VCBIN:=$(VS_PATH)/VC/bin/x86_amd64)
        $(eval CFLAGS   += -DHL_PRFMAXSO_I=4 -DHL_PRFMAXSO_L=4 -DHL_PRFMAXSO_LL=8)

		$(if $(filter $(BTYPE),release),
	    	$(eval CFLAGS   += -DWIN32 -DWIN64\
                               $(WinGen_CFLAGS) $(WinRel_CFLAGS))
	    	$(eval LDFLAGS  := -MACHINE:X64\
                               $(WinGen_LDFLAGS) $(WinRel_LDFLAGS)\
                               -LIBPATH:'$(VCLIB)/amd64';'$(SDKLIB)/amd64')
	    	$(eval RCFLAGS  := -DWIN64 -DNDEBUG\
                               $(WinGen_RCFLAGS) $(WinRel_RCFLAGS))
	    	$(eval CVTFLAGS := -NOLOGO -MACHINE:X64\
                               $(WinGen_CVTFLAGS) $(WinRel_CVTFLAGS))
		)

		$(if $(filter $(BTYPE),debug),
	    	$(eval CFLAGS   += -DWIN32 -DWIN64\
                               $(WinGen_CFLAGS) $(WinDeb_CFLAGS))
            $(if $(filter $(BINTYPE),LIB),
                $(eval LDFLAGS  := -MACHINE:X64\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)/amd64';'$(SDKLIB)/amd64')
            ,
	    	    $(eval LDFLAGS  := -MACHINE:X64 -DEBUG\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)/amd64';'$(SDKLIB)/amd64')
            )
	    	$(eval RCFLAGS  := -DWIN64 -D_DEBUG\
                               $(WinGen_RCFLAGS) $(WinDeb_RCFLAGS))
	    	$(eval CVTFLAGS := -NOLOGO -MACHINE:X64\
                               $(WinGen_CVTFLAGS) $(WinDeb_CVTFLAGS))
		)

		$(if $(filter $(BTYPE),insure),
	    	$(eval CFLAGS   += -DWIN32 -DWIN64\
                               $(WinGen_CFLAGS) $(WinDeb_CFLAGS))
            $(if $(filter $(BINTYPE),LIB),
                $(eval LDFLAGS  := -MACHINE:X64\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)/amd64';'$(SDKLIB)/amd64')
            ,
	    	    $(eval LDFLAGS  := -MACHINE:X64 -DEBUG\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)/amd64';'$(SDKLIB)/amd64')
            )
	    	$(eval RCFLAGS  := -DWIN64 -D_DEBUG\
                               $(WinGen_RCFLAGS) $(WinDeb_RCFLAGS))
	    	$(eval CVTFLAGS := -NOLOGO -MACHINE:X64\
                               $(WinGen_CVTFLAGS) $(WinDeb_CVTFLAGS))
		)


        $(if $(filter $(BINTYPE),EXE),
	    	$(eval LDFLAGS+=-LARGEADDRESSAWARE:NO)
        )

		$(eval MASM:=$(VCBIN)/ml64)
	)
	    
	$(if $(filter $(CPU),ipf),
	    $(eval VCBIN:=$(VS_PATH)/VC/bin/x86_ia64)

		$(if $(filter $(BTYPE),release),
	    	$(eval CFLAGS   += -DWIN32 -DWIN64 -D_IA64_\
                               $(WinGen_CFLAGS) $(WinRel_CFLAGS))
	    	$(eval LDFLAGS  := -MACHINE:IA64\
                               $(WinGen_LDFLAGS) $(WinRel_LDFLAGS)\
                               -LIBPATH:'$(VCLIB)/ia64';'$(SDKLIB)/ia64')
	    	$(eval RCFLAGS  := -DWIN64 -D_IA64_ -DNDEBUG\
                               $(WinGen_RCFLAGS) $(WinRel_RCFLAGS))
	    	$(eval CVTFLAGS := -NOLOGO -MACHINE:IA64\
                               $(WinGen_CVTFLAGS) $(WinRel_CVTFLAGS))
		)

		$(if $(filter $(BTYPE),debug),
	    	$(eval CFLAGS   += -DWIN32 -DWIN64 -D_IA64_\
                               $(WinGen_CFLAGS) $(WinDeb_CFLAGS))
            $(if $(filter $(BINTYPE),LIB),
	    	    $(eval LDFLAGS  := -MACHINE:IA64\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)/ia64';'$(SDKLIB)/ia64')
            ,
	    	    $(eval LDFLAGS  := -MACHINE:IA64 -DEBUG\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)/ia64';'$(SDKLIB)/ia64')
            )
	    	$(eval RCFLAGS  := -DWIN64 -D_IA64_ -D_DEBUG\
                               $(WinGen_RCFLAGS) $(WinDeb_RCFLAGS))
	    	$(eval CVTFLAGS := -NOLOGO -MACHINE:IA64\
                               $(WinGen_CVTFLAGS) $(WinDeb_CVTFLAGS))
		)

		$(if $(filter $(BTYPE),insure),
	    	$(eval CFLAGS   += -DWIN32 -DWIN64 -D_IA64_\
                               $(WinGen_CFLAGS) $(WinDeb_CFLAGS))
            $(if $(filter $(BINTYPE),LIB),
	    	    $(eval LDFLAGS  := -MACHINE:IA64\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)/ia64';'$(SDKLIB)/ia64')
            ,
	    	    $(eval LDFLAGS  := -MACHINE:IA64 -DEBUG\
                                   $(WinGen_LDFLAGS) $(WinDeb_LDFLAGS)\
                                   -LIBPATH:'$(VCLIB)/ia64';'$(SDKLIB)/ia64')
            )
	    	$(eval RCFLAGS  := -DWIN64 -D_IA64_ -D_DEBUG\
                               $(WinGen_RCFLAGS) $(WinDeb_RCFLAGS))
	    	$(eval CVTFLAGS := -NOLOGO -MACHINE:IA64\
                               $(WinGen_CVTFLAGS) $(WinDeb_CVTFLAGS))
		)

	)


	$(eval CINC+=-I'$(VS_PATH)/VC/Include'             \
				 -I'$(VS_PATH)/VC/atlmfc/Include'      \
                 -I'$(VS_PATH)/VC/PlatformSDK/Include' \
				 -I'$(VS_PATH)/SDK/V2.0/Include'         )
               
	$(foreach ADD,$(DEFINES),
	    $(eval CFLAGS+=-D$(ADD))
	)           

	$(eval CFLAGS += -D_MBCS -D_WINDOWS\
                     -W4 -nologo -EHsc -c\
	                 -wd4996 -wd4267 -wd4127)
	
    $(foreach ADD,$(LIBS),
	    $(eval LDFLAGS+=$(BINDIRBASE)/$(BTYPE)/$(OS)/$(CPU)/$(LIBDIRADD)/$(ADD))
	)           

	$(eval CC:=$(VCBIN)/cl)
	$(if $(filter $(BTYPE),insure),
	    $(eval CC:=insure)
	)
    
	$(if $(filter $(BINTYPE),EXE),
	    $(eval LDFLAGS+=-nologo -MANIFEST -incremental:no)
	    $(eval LD:=$(VCBIN)/link)
		$(if $(filter $(BTYPE),insure),
		    $(eval LD:=inslink)
		)
	)
	$(if $(filter $(BINTYPE),DLL),
	    $(eval CFLAGS   += -D_USRDLL -D_WINDLL)
	    $(eval LDFLAGS  += -nologo -DLL -MANIFEST -incremental:no)
	    $(eval LD:=$(VCBIN)/link)
		$(if $(filter $(BTYPE),insure),
		    $(eval LD:=inslink)
		)
	)
	$(if $(filter $(BINTYPE),LIB),
	    $(eval LDFLAGS+=-nologo)
	    $(eval LD:=$(VCBIN)/lib)
	)

	$(eval INCFLAGS := $(filter -D%,$(CFLAGS)) )
   	$(eval MTFLAGS  += -NOLOGO)
	$(eval SYSLIBS  := $(Win_LIBS))

    $(eval RC:=rc)
    $(eval CVT:=cvtres)
    $(eval MT:=mt)
    $(eval RM:=del)
endef

# $(eval RC:=$(VS_PATH)/VC/bin/rc)
# $(eval CVT:=$(VS_PATH)/VC/bin/cvtres)
# $(eval MT:=$(VS_PATH)/VC/bin/mt)


#
# $(m_setup_linux)
#
# setup linux compiler and linker settings
# depending on selected target
#
define m_setup_linux
	$(eval LinRel_CFLAGS:=-O2 -g $(LinRel_CFLAGS))
	$(eval CFLAGS  += -c -DHL_LINUX -DHL_UNIX -std=c++0x -fvisibility=hidden -Wstrict-aliasing=2 \
	                  -D'HL_CPUTYPE="Linux $(CPU)"'\
	                  $(LinGen_CFLAGS))
	$(eval LDFLAGS := $(LinGen_LDFLAGS))

	$(if $(filter $(BTYPE),release),
		$(eval CFLAGS  += $(LinRel_CFLAGS))
		$(eval LDFLAGS += $(LinRel_LDFLAGS))
	)
	$(if $(filter $(BTYPE),debug),
		$(eval CFLAGS  += -O0 -g $(LinDeb_CFLAGS))
		$(if $(filter $(BINTYPE),LIB),
			$(eval LDFLAGS += $(LinDeb_LDFLAGS))
		,
			$(eval LDFLAGS += -g $(LinDeb_LDFLAGS))
		)
	)

	$(if $(filter $(CPU),x86),
		$(eval CFLAGS  += -m32 -DHL_PRFMAXSO_I=4 -DHL_PRFMAXSO_L=4 -DHL_PRFMAXSO_LL=8)
		$(if $(filter $(BINTYPE),LIB),
		,
			$(eval LDFLAGS += -m32)
		)
		$(eval ASM_FLAGS=-f elf32 -F dwarf -g)
	)
	$(if $(filter $(CPU),em64t),
		$(eval CFLAGS  += -m64 -DEM64T -DHL_PRFMAXSO_I=4 -DHL_PRFMAXSO_L=8 -DHL_PRFMAXSO_LL=8)
		$(if $(filter $(BINTYPE),LIB),
		,
			$(eval LDFLAGS += -m64)
		)
		$(eval ASM_FLAGS=-f elf64 -F dwarf -g)
	)

	$(eval CINC    += -I/usr/local/include -I/usr/include)
	$(eval SYSLIBS := $(Lin_LIBS))

	$(foreach ADD,$(DEFINES),
		$(eval CFLAGS+=-D$(ADD))
	)           
	$(foreach ADD,$(LIBS),
		$(eval SYSLIBS+=-L$(BINDIRBASE)/$(BTYPE)/$(OS)/$(CPU)/$(LIBDIRADD)/$(dir $(ADD)))
		$(eval SYSLIBS+=-l$(subst $(LIBTYPE),,$(subst $(LIBPREFIX),,$(notdir $(ADD)))))
	)


	$(if $(filter $(BINTYPE),EXE),
		$(eval LD:=gcc)
	)
	$(if $(filter $(BINTYPE),DLL),
		$(eval LD:=gcc)
		$(eval CFLAGS  += -fPIC)
		$(eval LDFLAGS += -shared -shared-libgcc)
	)
	$(if $(filter $(BINTYPE),LIB),
		$(eval LD:=ar)
		$(eval CFLAGS  += -fPIC)
		$(eval LDFLAGS += rcs)
	)

	$(eval CC:=gcc)
	$(eval AS:=nasm)
	$(eval RM:=rm -f)
endef


#
# $(m_setup_solaris)
#
# setup solaris compiler and linker settings
# depending on selected target
#
define m_setup_solaris
	$(eval SolRel_CFLAGS:=-xO3 $(SolRel_CFLAGS))
	$(eval CFLAGS  += -c -DHL_SOLARIS -DHL_BIG_ENDIAN\
                      -DHL_UNIX -D'HL_CPUTYPE="Solaris $(CPU)"'\
                      $(SolGen_CFLAGS))
	$(eval LDFLAGS := $(SolGen_LDFLAGS))

	$(if $(filter $(BTYPE),release),
		$(eval CFLAGS  += $(SolRel_CFLAGS))
		$(eval LDFLAGS += $(SolRel_LDFLAGS))
    )
	$(if $(filter $(BTYPE),debug),
		$(eval CFLAGS  += -g $(SolDeb_CFLAGS))
		$(eval LDFLAGS += -g $(SolDeb_LDFLAGS))
	)

	$(if $(filter $(CPU),em64t),
		$(eval CFLAGS  += -xarch=amd64)
		$(eval LDFLAGS += -xarch=amd64)
	)
	$(if $(filter $(CPU),sparc64),
		$(eval CFLAGS  += -xarch=v9)
		$(eval LDFLAGS += -xarch=v9)
	)
	
	$(foreach ADD,$(DEFINES),
	    $(eval CFLAGS+=-D$(ADD))
	)           

	$(eval CINC    += -I/usr/include)
	$(eval SYSLIBS := $(Sol_LIBS))

	
	$(if $(filter $(BINTYPE),EXE),
	)
	$(if $(filter $(BINTYPE),DLL),
	    $(eval CFLAGS  += -G -Kpic)
	    $(eval LDFLAGS += -G -Kpic)
	)
	$(if $(filter $(BINTYPE),LIB),
	)

	
    $(eval CC:=CC)
	$(eval LD:=CC)
	$(eval RM:=rm -f)
endef


#
# $(m_setup_hpux)
#
# setup hpux compiler and linker settings
# depending on selected target
#
define m_setup_hpux
	$(if $(filter $(BTYPE),debug),
		$(eval CFLAGS+=-g0),
		$(eval CFLAGS+=+O4 +Oconservative)
	)
	$(if $(filter $(CPU),parisc),
		$(eval CFLAGS+=+DA2.0W)
	)
	$(if $(filter $(CPU),ipf),
		$(eval CFLAGS+=+DD64 -DHL_IPF -D_IA64_)
	)

	$(eval CFLAGS+=-c -mt -AA +z +W2191,829\
				   -D__HOB_ALIGN__ -D_REENTRANT\
                   -D_THREAD_SAFE -D_THREAD_SAFE_ERRNO\
                   -DHL_HPUX -DHL_BIG_ENDIAN\
                   -DHL_UNIX -D'HL_CPUTYPE="HPUX $(CPU)"')

	$(foreach ADD,$(DEFINES),
	    $(eval CFLAGS+=-D$(ADD))
	)           


	$(eval CINC+=-I/opt/aCC/include* -I/usr/include)

	
	$(if $(filter $(CPU),parisc),
		$(eval LDFLAGS:=+DA2.0W)
	)
	$(if $(filter $(CPU),ipf),
		$(eval LDFLAGS:=+DD64)
	)
	$(if $(filter $(BTYPE),debug),
		$(eval LDFLAGS+=-g0)
	)
	$(eval LDFLAGS+=-mt -AA -mt -b -L/usr/lib)
	$(eval SYSLIBS:=-lnsl -ldl)
	
    $(eval CC:=aCC)
	$(eval LD:=aCC)
	$(eval RM:=rm -f)
endef


#
# $(m_setup_aix)
#
# setup aix compiler and linker settings
# depending on selected target
#
define m_setup_aix
	$(if $(filter $(BTYPE),debug),
		$(eval CFLAGS+=-g),
		$(eval CFLAGS+=-O2)
	)
	$(eval CFLAGS+=-c -q64 -qpic -qchars=signed\
				   -qthreaded -fPIC -qsuppress=1540-1281\
				   -D__HOB_ALIGN__ -D_REENTRANT\
                   -D_THREAD_SAFE -D_THREAD_SAFE_ERRNO\
                   -DHL_AIX -DHL_BIG_ENDIAN\
				   -DXML_USE_PTHREADS\
                   -DHL_UNIX -D'HL_CPUTYPE="AIX $(CPU)"')

	$(foreach ADD,$(DEFINES),
	    $(eval CFLAGS+=-D$(ADD))
	)           


	
	$(eval LDFLAGS:=-q64 -qthreaded -qmkshrobj -qpic -G -L/usr/lib)
	$(if $(filter $(BTYPE),debug),
		$(eval LDFLAGS+=-g)
	)
	$(eval SYSLIBS:=-lpthreads -lnsl -ldl -lxti)
	
    $(eval CC:=xlC)
	$(eval LD:=xlC)
	$(eval RM:=rm -f)
endef

#
# $(m_setup_freebsd)
#
# setup freebsd compiler and linker settings
# depending on selected target
#
# notes: currently use Linux flags also for FreeBSD
#
#        gcc option "-mt" filtered out from Linux linker flags for compiling
#        with clang compiler on FreeBSD (finkml, 25.02.2016)
#
define m_setup_freebsd
	$(eval LinRel_CFLAGS:=-O2 -g $(LinRel_CFLAGS))
	$(eval CFLAGS  += -c -DHL_FREEBSD -DHL_UNIX -fvisibility=hidden \
	                  -D'HL_CPUTYPE="FreeBSD $(CPU)"'\
	                  $(LinGen_CFLAGS))
	$(eval LDFLAGS := $(filter-out -mt,$(LinGen_LDFLAGS)))

	$(if $(filter $(CPU),em64t),
		$(eval CFLAGS  += -DEM64T -DHL_PRFMAXSO_I=4 -DHL_PRFMAXSO_L=8 -DHL_PRFMAXSO_LL=8)
	)

	$(if $(filter $(BTYPE),release),
		$(eval CFLAGS  += $(LinRel_CFLAGS))
		$(eval LDFLAGS += $(LinRel_LDFLAGS))
	)
	$(if $(filter $(BTYPE),debug),
		$(eval CFLAGS  += -O0 -g $(LinDeb_CFLAGS))
		$(if $(filter $(BINTYPE),LIB),
			$(eval LDFLAGS += $(LinDeb_LDFLAGS))
		,
			$(eval LDFLAGS += -g $(LinDeb_LDFLAGS))
		)
	)

	$(if $(filter $(CPU),x86),
		$(eval ASM_FLAGS=-f elf32 -F dwarf -g)
	)
	$(if $(filter $(CPU),em64t),
		$(eval ASM_FLAGS=-f elf64 -F dwarf -g)
	)

	$(eval CINC    += -I/usr/include -I/usr/local/include)
	$(eval SYSLIBS := $(Bsd_LIBS))

	$(foreach ADD,$(DEFINES),
		$(eval CFLAGS+=-D$(ADD))
	)           
	$(foreach ADD,$(LIBS),
		$(eval SYSLIBS+=-L$(BINDIRBASE)/$(BTYPE)/$(OS)/$(CPU)/$(LIBDIRADD)/$(dir $(ADD)))
		$(eval SYSLIBS+=-l$(subst $(LIBTYPE),,$(subst $(LIBPREFIX),,$(notdir $(ADD)))))
	)


	$(if $(filter $(BINTYPE),EXE),
		$(eval LD:=clang)
	)
	$(if $(filter $(BINTYPE),DLL),
		$(eval LD:=clang)
		$(eval CFLAGS  += -fPIC)
		$(eval LDFLAGS += -shared -shared-libgcc)
	)
	$(if $(filter $(BINTYPE),LIB),
		$(eval LD:=ar)
		$(eval CFLAGS  += -fPIC)
		$(eval LDFLAGS += rcs)
	)

	$(eval CC:=clang)
	$(eval AS:=nasm)
	$(eval RM:=rm -f)
endef

#
# $(m_setting_overview)
#
# write a overview over all setting (if DEBUG)
#
define m_setting_overview
	$(call m_dprint, Compiler:        $(CC)       )
	$(call m_dprint, CFLAGS:          $(CFLAGS)   )
	$(call m_dprint, CINC:            $(CINC)     )
	$(call m_dprint, Linker:          $(LD)       )
	$(call m_dprint, LDFLAGS:         $(LDFLAGS)  )
	$(call m_dprint, BIN-Directory:   $(BINDIR)   )
	$(call m_dprint, OBJ-Directory:   $(OBJDIR)   )
	$(call m_dprint, Objects:         $(OBJECTS)  )
	$(call m_dprint, GetHeader:       $(GETHDR)   )
	$(call m_dprint, Headers:         $(HEADERS)  )
	$(call m_dprint, WinFiles:        $(WinFiles) )
	$(call m_dprint, UnixFiles:       $(UnixFiles))
endef


#
# $(m_compile)
#
# compiling function
#
define m_compile
    
	$(call m_checkdir,$(dir $@))
    
	$(if $(filter $(OS),windows),
            $(call m_checkdir,$(OBJDIR)/src/)
	    $(if $(filter $(BTYPE),debug),
            @'$(CC)' $(CFLAGS) $(CINC) -FAcs -Fa'$(basename $@).cod' -Fo'$@' -Fd'$(OBJDIR)/src/' '$<'
	    )
	    $(if $(filter $(BTYPE),insure),
            @'$(CC)' $(CFLAGS) $(CINC)  -Fo'$@' -Fd'$(OBJDIR)/src/' '$<'
	    )
	    $(if $(filter $(BTYPE),release),
            @'$(CC)' $(CFLAGS) $(CINC) -FAcs -Fa'$(basename $@).cod' -Fo'$@' -Fd'$(OBJDIR)/src/' '$<'
	    ),

    	$(call m_print,compiling $(notdir $<))
	$(if $(filter $(OS),freebsd),
	  $(if $(filter $(notdir $<),xs-encry-1.cpp),
	    $(eval CFLAGS := $(filter-out -O2,$(CFLAGS)))
	  )
	)
	    @$(CC) $(CFLAGS) $(CINC) -o '$@' '$<'
    )
endef

#
# $(m_comp_res)
#
# compile resources (only for windows)
#
define m_comp_res
	$(if $(filter $(OS),windows),
	    $(if $(filter %.rc,$(RESFILE)),
	        $(call m_dprint,compile resource $(RESFILE))
	        $(eval RESOBJECT=$(subst $(RESDIR),$(OBJDIR),$(basename $(RESFILE)).res$(OBJTYPE)))
	        @$(RC) $(RCFLAGS) $(CINC) -fo'$(subst $(RESDIR),$(OBJDIR),$(basename $(RESFILE)).res)' $(RESFILE)
	        @$(CVT) $(CVTFLAGS) -OUT:$(RESOBJECT) '$(subst $(RESDIR),$(OBJDIR),$(basename $(RESFILE)).res)'
	    )
    )
endef

#
# $(m_compile_asm)
#
# compiling function
#
define m_compile_asm
    
	$(call m_checkdir,$(dir $@))
    
	$(if $(filter $(OS),windows),
            $(call m_checkdir,$(OBJDIR)/src/)
    	$(call m_print,compiling $(notdir $<))
		$(call m_print,@'$(MASM)' -c -Cx -Fo'$@' '$<')
	    @'$(MASM)' -c -Cx -Fo'$@' '$<'
    )
endef

#
# $(m_compile_s)
#
# compiling function
#
define m_compile_s
    $(call m_checkdir,$(dir $@))
    $(if $(filter $(OS),windows),
        ,
        $(call m_checkdir,$(OBJDIR)/src/)
        $(call m_print,compiling $(notdir $<))
        $(call m_print,@$(AS) $(ASM_FLAGS) -o '$@' '$<')
        @$(AS) $(ASM_FLAGS) -o '$@' '$<'
    )
endef

#
# $(m_link)
#
# link function
#
define m_link
	$(call m_print,Linking $@)
	
	$(call m_checkdir,$(BINDIR))
	
	$(if $(filter $(OS),windows),
	    $(if $(filter $(BINTYPE),LIB),
	        @'$(LD)' $(LDFLAGS) $(SYSLIBS) -OUT:'$@' $(OBJECTS)
        ,
	        $(if $(filter $(BTYPE),debug),
	            @'$(LD)' $(LDFLAGS) $(SYSLIBS) -OUT:'$@' -MAP:'$(basename $@).map' -IMPLIB:'$(basename $@).lib' -MANIFESTFILE:'$(basename $@).manifest' -PDB:'$(basename $@).pdb' $(OBJECTS) $(RESOBJECT)
	        )
	        $(if $(filter $(BTYPE),insure),
	            @'$(LD)' $(LDFLAGS) $(SYSLIBS) -OUT:'$@' -MAP:'$(basename $@).map' -IMPLIB:'$(basename $@).lib' -MANIFESTFILE:'$(basename $@).manifest' -PDB:'$(basename $@).pdb' $(OBJECTS) $(RESOBJECT)
	        )
	        $(if $(filter $(BTYPE),release),
	            @'$(LD)' $(LDFLAGS) $(SYSLIBS) -OUT:'$@' -MAP:'$(basename $@).map' -IMPLIB:'$(basename $@).lib' -MANIFESTFILE:'$(basename $@).manifest' $(OBJECTS) $(RESOBJECT)
	        )
		)
	,

	    $(if $(filter $(BINTYPE),LIB),
	       @$(LD) $(LDFLAGS) $(SYSLIBS) '$@' $(OBJECTS)
        ,
	       @$(LD) $(LDFLAGS) $(OBJECTS) $(SYSLIBS) -o '$@'
           $(if $(filter $(BTYPE),release),
               cd $(abspath $(dir $@)) && \
               cp '$(notdir $@)' '$(notdir $@)'.debug && \
               strip --strip-debug '$(notdir $@)' && \
               objcopy --add-gnu-debuglink='$(notdir $@)'.debug '$(notdir $@)'
           )
		)
	)
endef


#
# $(m_embed_manifest)
#
# embed manifest function (only for windows)
#
define m_embed_manifest
	$(if $(filter $(OS),windows),
	    $(if $(filter $(BINTYPE),LIB),,
		    $(call m_dprint,Embedding Manifest $@)
            @$(MT) $(MTFLAGS) -outputresource:'$@;#2' -manifest '$(basename $@).manifest'
        )
	)
endef


#
# $(m_cleanup)
#
# delete object files and executables
#
define m_cleanup
	$(if $(filter $(OS),windows),
        $(call m_dprint,remove object files)
	    $(foreach ELEM,$(OBJECTS),
            -@$(RM) "$(subst /,\,$(basename $(ELEM)).*)"
        )
        $(call m_dprint,remove binary files)
        -@$(RM) "$(subst /,\,$(basename $(OUTNAME)).*)",

        $(call m_dprint,remove object files)
	    $(foreach ELEM,$(OBJECTS),
            @$(RM) $(basename $(ELEM)).*
        )
        $(call m_dprint,remove binary files)
        @$(RM) $(basename $(OUTNAME))*
    )
endef


# 
# $(call m_checkdir,directory)
# 
# check if directory exists, otherwise create it
#
define m_checkdir
	$(call m_dprint,Check dir $1)
	$(if $(filter $(OS),windows),
	    @IF NOT EXIST "$(subst /,\,$1)" md "$(subst /,\,$1)",
        @mkdir -p $1
    )
endef


#
# $(call m_dprint,string)
#
# print outputs if DEBUG Flag is set
#
define m_dprint
	$(if $(DEBUG),
		$(call m_print,$1)
	)
endef


#
# $(call m_print, string)
#
# print String on console
#
define m_print
    @echo $1
endef


#
# $(m_help)
#
# print usage information
#
define m_help
    $(call m_print,Makefile for building $(PROJECTNAME)       )
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

# Setup all variables for current PLATFORM
call_macro := $(m_setup)
