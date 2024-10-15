RDVPN 2.1 Solution                             Michael Jakobs, 09.06.2010
==================                             ==========================

Repository URL: https://linux02.hob.de/repos/RDVPN_2/RDVPN-2.1

This is an OS independent solution to build all RDVPN 2.1 (C/C++)
projects. GMAKE is used for building on all platforms.
Repository contains all needed Makefiles and gmake itself.


ATTENTION with xerces:
======================
    Due to KB, this solution contains everything you need to run WSP with
    it ServerDataHooks, except xerces header files. To save diskspace
    Xerces should be stored just once at HOB, please find it at
    
        \\hobc02k.hob.de\disk_d\Xerces\xerces-c-3.1.0\src

    To keep project as independent as possible an enviroment variable
    "XERCES_SRC" is used for finding xerces header files.

    If you aren't building at hobc02k (which holds this variable for all
    users), PLEASE SET ENVIROMENT VARIABLE "XERCES_SRC" ON YOUR BUILDING
    MACHINE.


Solution schema:
================
    RDVPN-2.1 solution contains an "master" Makefile

        ./RDVPN-2.1/src/build.mk

    It contains general (compiler, linker, etc) settings for all 
    different platforms and supports building exe-, dll- and lib-files.
    There is NO need to EDIT this file.

    Every project itself contains a Makefile, i.e.

        ./RDVPN-2.1/src/wsp/Makefile

    This Makefile controls, which files are compiled, which libraries are
    linked, which defines are set and so on.
    If you want to change any project settings, edit this Makefile!
 
    I have tried to keep Makefiles as easy as possible. So you won't need
    some knowledge about gmake, to edit these files.


WSP:
====
    Until now, KB doesn't commit his WSP into a repository. This solution
    holds a COPY of his sources. You can update WSP sources (only on
    hobc02k) using the batchfile

        ./RDVPN-2.1/src/wsp/update.bat

    which will update WSP sources from list in

        ./RDVPN-2.1/src/wsp/Makefile


NOTE for different platforms:
=============================

Windows:
--------
    We are using Visual Studio 2005 (VC8) for building RDVPN 2.1. The
    projects are configured as Makefile Projects, so don't be suprised if
    you find a lot of options disabled in VS GUI. Use the Makefiles to
    configure your build instead.

    If you want to add a new file to a project, it is not enough to add
    it with VS. You'll have to add it to the Makefile too!

    It can happen, that a first build-run for the whole solution will end
    in errors, because the solution contains a lot of dependencies and VS
    always builds more than one project at same time. In this case start
    a second build for the solution.

Unix/Linux:
-----------
    There exist a "solution" makefile

        ./RDVPN-2.1/src/Makefile

    which will create all needed projects for RDVPN-2.1.

    NOTE:
      Until now WSP2.3 does not yet exist for Unix Platforms, so you will
      not get a working UNIX RDVPN 2.1. KB first wants to finish the
      Windows Version!
