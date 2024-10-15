#!"C:/Program Files (x86)/Perl/bin/perl.exe"

#########################################################################################
# This is the "configuration file" for the RDVPN build process.							#
# Here you can manage every important setting.											#
# a short description is given for every point											#
# 2012 hofmants																			#
#########################################################################################

#########################################################################################
# hardcoded path for the perl library. if this changes, pray to Herrgott that he will	#
# set the paths correctly, otherwise you have to edit the following line				#
#########################################################################################
push( @INC, "C:\\Program Files (x86)\\Perl\\lib\\File\\" );

#########################################################################################
# Logfile File Names:																	#
# We have two different logfiles, one for the prepare-, and one for the build process	#
# here you can set the variable parts of the logfiles									#
# DATE		will be expanded to the current date										#
# TIME		will be expanded to the current time										#
# SVN		is the subversion version number											#
#																						#
# date_format: change the style of the date string, valid is DAY, MON and YEAR			#
# time_format: appearance of the time string, valid: HOUR, MIN, SEC						#
#########################################################################################
$prepare_log	= "prepare.DATE__TIME__svnSVN.txt";
$build_log		= "build.DATE__TIME__svnSVN.txt";

$date_format	= "YEAR-MON-DAY";
$time_format	= "HOUR-MIN-SEC";

#########################################################################################
# We are starting from the \\installer folder, unless otherwise stated					#
#																						#
# $logfile1				-> Folder of the logfile - prepare process						#
# $logfile2				-> Folder of the logfile - build process						#
# $versiontable			-> Path to the file where the versiontable is constructed		#
# $sourcepath			-> source path for the build process files						#
# $targetpath			-> destination path for the filtered files						#
# $rdvpn_version_file	-> Path to the rdvpn version file, will be treated special		#
# $buildfile			-> File, which includes the build number						#
# $zip_command			-> which program you want to use to zip the tunnel files		#
# $ppp_source			-> path to the tunnel files										#
# $sign_jar_bat			-> the batch file which signs the .jar file,					#
#							relative from $ppp_source folder							#
# $ppp_target			-> where to copy the signed jar file,							#
#							relative from $ppp_source folder							#
# $installer_path		-> path back to the installer folder,							#
#							relative from $ppp_source folder							#
# $tunnel_zip			-> name of the zip file made of the tunnel files				#
# $tunnel_jar			-> name of the jar file											#
# $pppfiles{os_arch}	-> which files to pack into the archive							#
# $install_any_exe		-> Path to InstallAnywhere executable							#
# $ia_xml_file			-> Path to InstallAnywhere xml config							#
# $ia_output_folder		-> Path to the Installer ( EDITION and PLATFORM will be			#
#						   replaced correctly )											#
# $sign_single_path		-> Path to Script for signing the software						#
# $sign_single_bat		-> Script for signing the software								#
# $install_folder		-> relative path to \installer (from sign-single.bat folder)	#
# $dvd_path				-> path were the installer should be moved to ( EDITION and		#
#						   platform will be replaced )									#
# @extensions			-> folders with the additional software							#
# $extension_source		-> from where they come											#
# $extension_destination-> and where they should be copied								#
# $extension_dvd_dest	-> where they should be moved on the DVD						#
# $cmd_del_target		-> command for clearing the rdvpn folder ( eg. $targetpath )	#
# $dvd_source			-> the folder which contains all the finished installers		#
# $dvd_target			-> the path where to copy the finished installers				#
# $comp_infos           -> pattern for globbing all RD VPN component info files in the final $dvd_target #
# $hobids               -> pattern for globbing all HOBID files in the final $dvd_target         #
#########################################################################################
$logfile_prepare		= "log\\";
$logfile_build			= "log\\";
$versiontable			= "log\\versions.txt";

$sourcepath				= "..\\..\\binaries\\www";
$targetpath				= "www\\";

$rdvpn_version_file		= "..\\binaries\\version.txt";
$buildfile				= "..\\SVN_VER.txt";
$zip_command			= "C:\\Program Files\\7-Zip\\7z.exe";
$ppp_source				= "..\\binaries\\preinstall\\ppptunnel\\";
$sign_jar_bat			= "sign-jar.bat"; # relative from $ppp_source folder
$ppp_target				= "..\\..\\www\\public\\lib\\ppptunnel\\"; # relative from $ppp_source folder
$installer_path			= "..\\..\\..\\installer\\"; # relative from $ppp_source folder
$tunnel_zip				= "tunnelclient.zip";
$tunnel_jar				= "tunnelclient.jar";
$pppfiles{win_x86}		= [ "ibhpppt1.exe",  "command", "HOB-PPP-T1-01.pbk", "HOBmscaCS.dll", "HOBmscrAp.dll", "HOBsecCTE.dll" ];
$pppfiles{win_em64t}	= [ "ibhpppt1.exe",  "command", "HOB-PPP-T1-01.pbk", "HOBmscaCS.dll", "HOBmscrAp.dll", "HOBsecCTE.dll" ];
$pppfiles{mac_x86}		= [ "nbhpppt2.app", "command" ];
$pppfiles{mac_em64t}	= [ "nbhpppt2.app", "command" ];
$pppfiles{lin_x86}		= [ "nbhpppt2", "command" ];
$pppfiles{lin_em64t}	= [ "nbhpppt2", "command" ];
$install_any_exe		= "C:\\Program Files (x86)\\InstallAnywhere 2013\\build.exe";
$ia_xml_file			= "IAproject\\main_complete.iap_xml";
$ia_output_folder		= "IAproject\\main_complete_Build_Output\\EDITION\\Web_Installers\\InstData\\PLATFORM\\VM\\";
#$ia_output_folder		= "IAproject\\main_complete_Build_Output\\EDITION\\Web_Installers\\InstData\\PLATFORM\\";
$sign_single_path		= "..\\wsp-sdhs";
$sign_single_bat		= "sign-single.bat";
$install_folder			= "..\\installer\\"; # relative from wsp-sdhs folder
$dvd_path				= "..\\build-output\\DVD\\EDITION\\software\\RDVPN\\";
@extensions				= ( "vdiwsp", "wolagent", "wtslb", "hl_secu_mgr", "wolagent_hyperv" );
$extension_source		= "..\\binaries\\preinstall";
$extension_destination	= "..\\binaries\\www\\protected\\portlets\\globaladmin\\install";
$extension_dvd_dest		= "..\\build-output\\DVD\\EDITION\\software\\";
$cmd_del_target			= "rmdir /S /Q $targetpath";
$dvd_source				= "..\\build-output\\DVD";
$dvd_target				= "..\\..\\";
$comp_infos            = "$dvd_target*\\RDVPN_Component_Info.txt";
$hobids                = "$dvd_target*\\HOBID.xml";

#########################################################################################
# Here you can add new operating systems, architectures and editions					#
# just add the new name to the @valid_XXX arrays and write in the combos list,			#
# which operating system supports which architecture.									#
# everything else is done by the scripts.												#
#########################################################################################
@valid_os		= ( "win", "lin", "sol", "bsd", "aix", "hpux" );
@valid_arch		= ( "x86", "em64t", "ipf", "sparc", "ppc" );
@valid_edition	= ( "blue", "red", "green", "net", "exp", "dev", "ignore" );
# dev and ignore are only defined for excluding files and directories (don't build these "editions")

$combos{win}	= [ "x86", "em64t" ];
$combos{lin}	= [ "x86", "em64t", "ipf" ];
$combos{sol}	= [ "em64t", "sparc" ];
$combos{bsd}	= [ "x86", "em64t" ];
$combos{aix}	= [ "ppc" ];
$combos{hpux}	= [ "ipf" ];

#########################################################################################
# This Hash is used to generate the correct parameters for Install Anywhere				#
#########################################################################################
$ia_parameter{blue}		= "blue_edition";
$ia_parameter{red}		= "red_edition";
$ia_parameter{green}	= "green_edition";
$ia_parameter{net}		= "NetAccess";
$ia_parameter{exp}		= "Express";
$ia_parameter{win}		= "+WV +opt";
$ia_parameter{lin}		= "+LV +opt";
$ia_parameter{sol}		= "+S";
$ia_parameter{bsd}		= "+U";
$ia_parameter{aix}		= "+A";
$ia_parameter{hpux}		= "+H";

#########################################################################################
# |--- +++ --- +++ --- +++ --- +++ --- +++ --- +++ --- +++ --- +++ --- +++ --- +++ ---|	#
# |                    END OF IMPORTANT SETTINGS! Dont edit below!					  |	#
# |--- +++ --- +++ --- +++ --- +++ --- +++ --- +++ --- +++ --- +++ --- +++ --- +++ ---|	#
#########################################################################################

# internal perl module
use Fcntl ':flock';

# turn off buffering for file writes
$| = 1;

# function which handles the logfile
sub write_log
{
	my $logfile	= shift();
	my $msg		= shift();
	
	open( LOG, ">>", $logfile ); 
    flock( LOG, LOCK_EX );
	print LOG localtime(time()) . ": " . $msg;
	flock( LOG, LOCK_UN );
	close( LOG );
	return(0);
}

sub get_log_name
{
	my $which = shift();
	my $version;
	
	#   0    1    2     3     4    5     6     7     8
    #($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)
	my @timeinfo = localtime();
	
	my $sec		= $timeinfo[0];
	if( $sec < 10 ){ $sec = "0" . $sec };
	
	my $min		= $timeinfo[1];
	if( $min < 10 ){ $min = "0" . $min };
	
	my $hour	= $timeinfo[2];
	if( $hour < 10 ){ $hour = "0" . $hour };
	
	my $day		= $timeinfo[3];
	if( $day < 10 ){ $day = "0" . $day };
	
	my $mon		= $timeinfo[4] + 1;
	if( $mon < 10 ){ $mon = "0" . $mon };
	
	my $year	= $timeinfo[5] + 1900;
	
	$date_format =~ s/DAY/$day/g;
	$date_format =~ s/MON/$mon/g;
	$date_format =~ s/YEAR/$year/g;
	
	$time_format =~ s/HOUR/$hour/g;
	$time_format =~ s/MIN/$min/g;
	$time_format =~ s/SEC/$sec/g;
	
	open( SVN, "<", $buildfile );
	$version = <SVN>;
	chomp( $version );
	$version =~ s/\s//g;
	close( SVN );
	
	if( $which eq "prepare" )
	{
		$prepare_log =~ s/DATE/${date_format}/g;
		$prepare_log =~ s/TIME/${time_format}/g;
		$prepare_log =~ s/SVN/${version}/g;
		return( $logfile_prepare . $prepare_log );
	}
	else # uses always buildlog
	{
		$build_log =~ s/DATE/${date_format}/g;
		$build_log =~ s/TIME/${time_format}/g;
		$build_log =~ s/SVN/${version}/g;
		return( $logfile_build . $build_log );
	}
}

sub write_table
{
	my $versionfile = shift();
	my @file;
	my ( $name, $version, $new, $rdvpn );
	
	open( VF, "<", $versionfile );
    while( <VF> )
	{
		if( /name=(.*)/i ){ $name = $1; chomp( $name ); }
		if( /version=(.*)/i ){ $version = $1; chomp( $version ); }
	}
	close( VF );
	
	$rdvpn = 0;
	
	if( $versionfile eq $rdvpn_version_file )
	{
		open( SVN, "<", $buildfile );
		$version .= "." . <SVN>;
		chomp( $version );
		close( SVN );
		$rdvpn = 1;
	}
	
	$new = 1;
	if( -e $versiontable ){ $new = 0; }
	
	if( $new )
	{
		open( TABLE, ">", $versiontable ); 
		flock( TABLE, LOCK_EX );
		print TABLE "HOB RD VPN\n";
		print TABLE "==========\n";
		print TABLE "This file contains information about components of XNAMEX XVERSIONX\n\n";
		print TABLE "Version information:\n";
		print TABLE "--------------------\n";
		flock( TABLE, LOCK_UN );
		close( TABLE );
	}
	
	open( TABLE, "<", $versiontable ); 
	@file = <TABLE>;
	close( TABLE );
	
	if( $rdvpn )
	{
		foreach(@file)
		{
			if( /XNAMEX/ )
			{
				s/XNAMEX/$name/;
				s/XVERSIONX/$version/;
				last;
			}
		}
	}
	else
	{
		push( @file, "$name\t$version\n" );
	}
		
	# rewrite it
	open( TABLE, ">", $versiontable ); 
	flock( TABLE, LOCK_EX );
	print TABLE @file;
	flock( TABLE, LOCK_UN );
	close( TABLE );
	
	return(0);
}

sub get_version
{
	my $version;
	
	open( VF, "<", $rdvpn_version_file )
		or die("Error: Can't open $rdvpn_version_file: $!\n");
    while( <VF> )
	{
		if( /version=(.*)/i )
		{
			$version = $1;
			chomp( $version );
			last;
		}
	}
	close( VF );
	
	open( SVN, "<", $buildfile)
		or die("Error: Can't open $buildfile: $!\n");
	$version .= "." . <SVN>;
	chomp( $version );
	close( SVN );
	
	return( $version );
}

sub update_component_info {

    print "Updating component info and HOBID files ...\n\n";

    my $version_full = get_version();    # full RDVPN version, e.g., 2.1 12.6900
    $version_full =~ m/^(\d+\.\d+)\D/;
    my $version = $1;                   # RDVPN major version, e.g., 2.1
    my $year = 1900 + (localtime())[5]; # release year = current year, e.g., 2016

    print "Current version information:\n";
    print "  #rdvpn_version#:      $version\n";
    print "  #rdvpn_version_full#: $version_full\n";
    print "  #release_year#:       $year\n\n";

    # replace all placeholders in component info and hobid files by the actual values
    print "Files (relative to installer directory):\n";
    foreach my $fname ((glob($comp_infos), glob($hobids))) {
        # read all lines of the file
        print "  $fname\n";
        open(FILE_R, "<" . $fname)
            or die "Error: Could not open component file for reading: $!\n";
        my @lines = <FILE_R>;
        close(FILE_R);

        # make changes
        my $cnt = 0; # variable to count all substitutions made with the s/// operator
        foreach (@lines) {
            $cnt += s/#rdvpn_version#/$version/gi; # the s/// operator acts on current line (each element of @lines)
            $cnt += s/#rdvpn_version_full#/$version_full/gi;
            $cnt += s/#release_year#/$year/gi;
        }

        # write changed version back into file
        if ($cnt > 0) {
            open(FILE_W, ">" . $fname)
                or die "Error: Could not open component file for writing: $!\n";
            print FILE_W @lines;
            close(FILE_W)
                or die "Error when closing component file: $!\n";
        }
        print "  $cnt substitutions done.\n";
    }
    print "\n"
}

sub xcopy_ext_files
{
	my $log = shift();
	my $destination = shift();
	my ( $output, $errorcode );
	
	foreach( @extensions )
	{
		$output = `xcopy /e /i /f /y "${extension_source}\\$_" "${destination}\\$_\\" 2>&1`;
		$errorcode = $? / 256;
		$output =~ s/\n\n/\n/g;
		if($errorcode)
		{
			write_log( $log, "xcopy failed with code $errorcode! File $_\n$output\n" );
			return(1);
		}	
		write_log( $log, "xcopy copied $_ successfully!\n$output\n" );
	}
	return(0);
}
