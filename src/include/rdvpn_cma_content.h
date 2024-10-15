#ifndef RDVPN_CMA_CONTENT_H
#define RDVPN_CMA_CONTENT_H

struct dsd_cma_string
{
	int inc_offset;
	int inc_length;
};

#define HL_CMA_NAME_WEBTERM_RDP_SID "WEBTERM-RDP-SID"

struct dsd_webtermrdp_remoteapp {
	/** The environment variables in the WorkingDir field MUST be expanded on the server. */
	static const unsigned short TS_RAIL_EXEC_FLAG_EXPAND_WORKINGDIRECTORY = 0x1;
	/** The drive letters in the file path MUST be converted to corresponding mapped drives on the server. */
	static const unsigned short TS_RAIL_EXEC_FLAG_TRANSLATE_FILES = 0x2;
	/** If this flag is set, the ExeOrFile field refers to a file path. If it is not set, the ExeOrFile field refers to an executable. */
	static const unsigned short TS_RAIL_EXEC_FLAG_FILE = 0x4;
	/** The environment variables in the Arguments field MUST be expanded on the server. */
	static const unsigned short TS_RAIL_EXEC_FLAG_EXPAND_ARGUMENTS = 0x8;
	/** If this flag is set, the ExeOrFile field refers to an application user model ID. */
	static const unsigned short TS_RAIL_EXEC_FLAG_APP_USER_MODEL_ID = 0x10;

	unsigned short usc_flags;
	struct dsd_cma_string dsc_exe_or_file;
	struct dsd_cma_string dsc_working_dir;
	struct dsd_cma_string dsc_arguments;
};

struct dsd_webtermrdp_sid {
	struct dsd_cma_string dsc_user;
	struct dsd_cma_string dsc_password;
	struct dsd_cma_string dsc_domain;
	struct dsd_cma_string dsc_startmode;
	struct dsd_cma_string dsc_serverineta;
	int inc_serverport;
	struct dsd_webtermrdp_remoteapp dsc_remoteapp;
};

#endif /*!RDVPN_CMA_CONTENT_H*/
