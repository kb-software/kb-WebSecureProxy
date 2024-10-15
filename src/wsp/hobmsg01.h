//
//  Values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//


//
// Define the severity codes
//


//
// MessageId: HOB_INFO_001
//
// MessageText:
//
//  %1
//
#define HOB_INFO_001                     0x40000001L

//
// MessageId: HOB_INFO_002
//
// MessageText:
//
//  %1 %2
//
#define HOB_INFO_002                     0x40000002L

//
// MessageId: HOB_INFO_003
//
// MessageText:
//
//  %1 %2 %3
//
#define HOB_INFO_003                     0x40000003L

//
// MessageId: HOB_INFO_004
//
// MessageText:
//
//  %1 %2 %3 %4
//
#define HOB_INFO_004                     0x40000004L

//
// MessageId: HOB_INFO_005
//
// MessageText:
//
//  %1 %2 %3 %4 %5
//
#define HOB_INFO_005                     0x40000005L

//
// MessageId: HOB_INFO_011
//
// MessageText:
//
//  %1
//
#define HOB_INFO_011                     0x80000011L

//
// MessageId: HOB_INFO_012
//
// MessageText:
//
//  %1 %2
//
#define HOB_INFO_012                     0x80000012L

//
// MessageId: HOB_INFO_013
//
// MessageText:
//
//  %1 %2 %3
//
#define HOB_INFO_013                     0x80000013L

//
// MessageId: HOB_INFO_014
//
// MessageText:
//
//  %1 %2 %3 %4
//
#define HOB_INFO_014                     0x80000014L

//
// MessageId: HOB_INFO_015
//
// MessageText:
//
//  %1 %2 %3 %4 %5
//
#define HOB_INFO_015                     0x80000015L

//
// MessageId: HOB_INFO_021
//
// MessageText:
//
//  %1
//
#define HOB_INFO_021                     0xC0000021L

//
// MessageId: HOB_INFO_022
//
// MessageText:
//
//  %1 %2
//
#define HOB_INFO_022                     0xC0000022L

//
// MessageId: HOB_INFO_023
//
// MessageText:
//
//  %1 %2 %3
//
#define HOB_INFO_023                     0xC0000023L

//
// MessageId: HOB_INFO_024
//
// MessageText:
//
//  %1 %2 %3 %4
//
#define HOB_INFO_024                     0xC0000024L

//
// MessageId: HOB_INFO_025
//
// MessageText:
//
//  %1 %2 %3 %4 %5
//
#define HOB_INFO_025                     0xC0000025L

