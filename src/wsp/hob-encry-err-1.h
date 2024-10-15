#ifndef __HOB_ENCRY_ERROR_1__
#define __HOB_ENCRY_ERROR_1__
#ifdef _WIN32
#pragma once
#endif
//-----------------------------------------------------------------------------
// HMAC
//-----------------------------------------------------------------------------

#define	HMAC_OP_OK	0
#define	HMAC_NULL_PTR	-1
#define	HMAC_ALLOC_ERR	-2
#define	HMAC_PARAM_ERR	-3
#define	HMAC_DST_BUFFER_TOO_SMALL -4

//-----------------------------------------------------------------------------
// HMEM
//-----------------------------------------------------------------------------

#define	HMEM_OP_OK	0
#define	HMEM_NULL_PTR	-1
#define	HMEM_PARAM_ERR	-2
#define	HMEM_ALLOC_ERR	-3

//-----------------------------------------------------------------------------
// GMAC / AES_GCM
//-----------------------------------------------------------------------------

#define	GCM_OK	0
#define	GCM_NULL_PTR	-1
#define	GCM_ALLOC_ERR	-2
#define	GCM_PARAM_ERR	-3
#define	GCM_DST_BUFFER_TOO_SMALL -4
#define	GCM_AUTH_FAIL -5

//-----------------------------------------------------------------------------
// RNG
//-----------------------------------------------------------------------------

#define     PRGINI_NULL_PTR                     -1
#define     PRGINI_ALLOC_ERR                    -2

#define     PRGINI_NO_DIR_HANDLE                -620  // JAVA, directory handle fail
#define     PRGINI_NOT_A_DIRECTORY              -621  // JAVA, name not a directory
#define     PRGINI_GET_PATH_FAILED              -622  // JAVA, path resolve fail
#define     PRGINI_GET_FILELIST_FAIL            -623  // JAVA, no file list
#define     PRGINI_BASEINI_NULL_PTR             -624  // JAVA, no Runtime/Toolkit
#define     PRGINI_BASEINI_TOO_FEW_DATA         -625  // JAVA, to few data for INI
#define     PRGINI_THREAD_STOP_FAIL             -626  // JAVA, thread did not stop
#define     PRGINI_THREAD_START_FAIL            -627  // JAVA, thread did not start
#define     PRGINI_THREAD_DIED                  -628  // JAVA, abnormal thread death
#define     PRGINI_INVALID_THREAD_STATE         -629  // JAVA, thread in invalid state
#define     PRGINI_THREAD_CMD_FAIL              -630  // JAVA, thread not working
#define     PRGINI_STREAM_CLOSE_FAIL            -631  // JAVA, stream close failed
#define     PRGINI_PROCESS_START_FAIL           -632  // JAVA, process not started

#define     PRGINI_W32_SEED_HASH_FAIL           -633  // WIN32, seed generate failed
#define     PRGINI_W32_GET_OS_VERSION_FAIL      -634  // WIN32, Get OS Version fail

#define     PRGINI_NO_CMD                       -635  // UNIX, missing command
#define     PRGINI_NULLDEV_OPEN_FAIL            -636  // UNIX, /dev/nul open failed
#define     PRGINI_GET_PIPE_FAIL                -637  // UNIX, pipe create failed
#define     PRGINI_FORK_FAIL                    -638  // UNIX, could not fork
#define     PRGINI_CHILD_INP_TIMEOUT            -639  // UNIX, no data from child
#define     PRGINI_STDIN_READ_ERR               -640  // UNIX, read from pipe failed
#define     PRGINI_SELECT_ERR                   -641  // UNIX, select wrong mode
#define     PRGINI_WRONG_CHILD_PID              -642  // UNIX, got wrong child PID
#define     PRGINI_CHILD_ABNORMAL_TERMINATE     -643  // UNIX, child died abnormal

#define     DRBG_SEC_HASH_WEAK                  -669  // DRBG insufficient hash
#define     DRBG_SEC_TEST_FAILED                -670  // DRBG selfcheck failed
#define     DRBG_SEC_INIT_FAILED                -671  // DRBG initialize error
#define     DRBG_SEC_INIT_WEAK                  -672  // DRBG weak initialize error
#define     DRBG_SEC_RESEED_FAILED              -673  // DRBG reseeding error
#define     DRBG_SEC_RAND_FAILED                -674  // DRBG get random error

#define     DRBG_W32_GET_OS_VERSION_FAIL        PRGINI_W32_GET_OS_VERSION_FAIL
#define     DRBG_EXEC_NULLDEV_OPEN_FAIL         PRGINI_NULLDEV_OPEN_FAIL
#define     DRBG_EXEC_GET_PIPE_FAIL             PRGINI_GET_PIPE_FAIL
#define     DRBG_EXEC_FORK_FAIL                 PRGINI_FORK_FAIL
#define     DRBG_EXEC_CHILD_INP_TIMEOUT         PRGINI_CHILD_INP_TIMEOUT
#define     DRBG_EXEC_STDIN_READ_ERR            PRGINI_STDIN_READ_ERR
#define     DRBG_EXEC_SELECT_ERR                PRGINI_SELECT_ERR
#define     DRBG_EXEC_WRONG_CHILD_PID           PRGINI_WRONG_CHILD_PID
#define     DRBG_EXEC_CHILD_ABNORMAL_TERMINATE  PRGINI_CHILD_ABNORMAL_TERMINATE

#endif // !__HOB_ENCRY_ERROR_1__
