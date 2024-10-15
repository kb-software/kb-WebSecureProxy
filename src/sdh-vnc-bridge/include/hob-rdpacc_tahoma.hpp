#pragma once
#ifndef __HOB_RDPACC_tahoma_hpp__
#define __HOB_RDPACC_tahoma_hpp__


#ifndef __HOB_RDPACC_DSD_GLYPH_INFO__
#define __HOB_RDPACC_DSD_GLYPH_INFO__
struct dsd_glyph_info {
   short                isc_x;
   short                isc_y;
   unsigned short       usc_cx;
   unsigned short       usc_cy;
   unsigned short       usc_distance;
   const unsigned char* ucc_pattern;
   int                  inc_len_pattern;
};
#endif

// Glyph 0x20:  
const unsigned char ucrs_glyph_20[] = { 0 };
const dsd_glyph_info dss_glyph_info_20 = {0, 12, 0, 0, 4, ucrs_glyph_20, 0};

// Glyph 0x21: !
const unsigned char ucrs_glyph_21[] = {
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x00, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_21 = {1, 3, 1, 9, 4, ucrs_glyph_21, sizeof(ucrs_glyph_21)};

// Glyph 0x22: "
const unsigned char ucrs_glyph_22[] = {
   0xa0, 
   0xa0, 
   0xa0, 
};
const dsd_glyph_info dss_glyph_info_22 = {1, 2, 3, 3, 5, ucrs_glyph_22, sizeof(ucrs_glyph_22)};

// Glyph 0x23: #
const unsigned char ucrs_glyph_23[] = {
   0x14, 
   0x14, 
   0x7e, 
   0x28, 
   0x28, 
   0xfc, 
   0x28, 
   0x50, 
   0x50, 
};
const dsd_glyph_info dss_glyph_info_23 = {1, 3, 7, 9, 9, ucrs_glyph_23, sizeof(ucrs_glyph_23)};

// Glyph 0x24: $
const unsigned char ucrs_glyph_24[] = {
   0x20, 
   0x20, 
   0x70, 
   0xa8, 
   0xa0, 
   0x60, 
   0x30, 
   0x28, 
   0xa8, 
   0x70, 
   0x20, 
   0x20, 
};
const dsd_glyph_info dss_glyph_info_24 = {1, 2, 5, 12, 7, ucrs_glyph_24, sizeof(ucrs_glyph_24)};

// Glyph 0x25: %
const unsigned char ucrs_glyph_25[] = {
   0x61, 0x00, 
   0x92, 0x00, 
   0x92, 0x00, 
   0x94, 0x00, 
   0x64, 0xc0, 
   0x05, 0x20, 
   0x09, 0x20, 
   0x09, 0x20, 
   0x10, 0xc0, 
};
const dsd_glyph_info dss_glyph_info_25 = {0, 3, 11, 9, 12, ucrs_glyph_25, sizeof(ucrs_glyph_25)};

// Glyph 0x26: &
const unsigned char ucrs_glyph_26[] = {
   0x70, 
   0x88, 
   0x88, 
   0x50, 
   0x62, 
   0x92, 
   0x8c, 
   0x8c, 
   0x72, 
};
const dsd_glyph_info dss_glyph_info_26 = {0, 3, 8, 9, 8, ucrs_glyph_26, sizeof(ucrs_glyph_26)};

// Glyph 0x27: '
const unsigned char ucrs_glyph_27[] = {
   0x80, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_27 = {1, 2, 1, 3, 3, ucrs_glyph_27, sizeof(ucrs_glyph_27)};

// Glyph 0x28: (
const unsigned char ucrs_glyph_28[] = {
   0x20, 
   0x40, 
   0x40, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x40, 
   0x40, 
   0x20, 
};
const dsd_glyph_info dss_glyph_info_28 = {1, 2, 3, 12, 5, ucrs_glyph_28, sizeof(ucrs_glyph_28)};

// Glyph 0x29: )
const unsigned char ucrs_glyph_29[] = {
   0x80, 
   0x40, 
   0x40, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x40, 
   0x40, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_29 = {1, 2, 3, 12, 5, ucrs_glyph_29, sizeof(ucrs_glyph_29)};

// Glyph 0x2a: *
const unsigned char ucrs_glyph_2a[] = {
   0x20, 
   0xa8, 
   0x70, 
   0xa8, 
   0x20, 
};
const dsd_glyph_info dss_glyph_info_2a = {1, 2, 5, 5, 7, ucrs_glyph_2a, sizeof(ucrs_glyph_2a)};

// Glyph 0x2b: +
const unsigned char ucrs_glyph_2b[] = {
   0x10, 
   0x10, 
   0x10, 
   0xfe, 
   0x10, 
   0x10, 
   0x10, 
};
const dsd_glyph_info dss_glyph_info_2b = {0, 5, 7, 7, 8, ucrs_glyph_2b, sizeof(ucrs_glyph_2b)};

// Glyph 0x2c: ,
const unsigned char ucrs_glyph_2c[] = {
   0x40, 
   0x40, 
   0x40, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_2c = {0, 10, 3, 4, 4, ucrs_glyph_2c, sizeof(ucrs_glyph_2c)};

// Glyph 0x2d: -
const unsigned char ucrs_glyph_2d[] = {
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_2d = {0, 8, 3, 1, 4, ucrs_glyph_2d, sizeof(ucrs_glyph_2d)};

// Glyph 0x2e: .
const unsigned char ucrs_glyph_2e[] = {
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_2e = {1, 10, 1, 2, 4, ucrs_glyph_2e, sizeof(ucrs_glyph_2e)};

// Glyph 0x2f: /
const unsigned char ucrs_glyph_2f[] = {
   0x10, 
   0x10, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_2f = {0, 2, 4, 12, 5, ucrs_glyph_2f, sizeof(ucrs_glyph_2f)};

// Glyph 0x30: 0
const unsigned char ucrs_glyph_30[] = {
   0x78, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_30 = {0, 3, 6, 9, 7, ucrs_glyph_30, sizeof(ucrs_glyph_30)};

// Glyph 0x31: 1
const unsigned char ucrs_glyph_31[] = {
   0x20, 
   0xe0, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0xf8, 
};
const dsd_glyph_info dss_glyph_info_31 = {1, 3, 5, 9, 7, ucrs_glyph_31, sizeof(ucrs_glyph_31)};

// Glyph 0x32: 2
const unsigned char ucrs_glyph_32[] = {
   0x78, 
   0x84, 
   0x04, 
   0x04, 
   0x08, 
   0x30, 
   0x40, 
   0x80, 
   0xfc, 
};
const dsd_glyph_info dss_glyph_info_32 = {0, 3, 6, 9, 7, ucrs_glyph_32, sizeof(ucrs_glyph_32)};

// Glyph 0x33: 3
const unsigned char ucrs_glyph_33[] = {
   0x78, 
   0x84, 
   0x04, 
   0x04, 
   0x38, 
   0x04, 
   0x04, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_33 = {0, 3, 6, 9, 7, ucrs_glyph_33, sizeof(ucrs_glyph_33)};

// Glyph 0x34: 4
const unsigned char ucrs_glyph_34[] = {
   0x08, 
   0x18, 
   0x28, 
   0x48, 
   0x88, 
   0xfc, 
   0x08, 
   0x08, 
   0x08, 
};
const dsd_glyph_info dss_glyph_info_34 = {0, 3, 6, 9, 7, ucrs_glyph_34, sizeof(ucrs_glyph_34)};

// Glyph 0x35: 5
const unsigned char ucrs_glyph_35[] = {
   0xfc, 
   0x80, 
   0x80, 
   0xf8, 
   0x04, 
   0x04, 
   0x04, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_35 = {0, 3, 6, 9, 7, ucrs_glyph_35, sizeof(ucrs_glyph_35)};

// Glyph 0x36: 6
const unsigned char ucrs_glyph_36[] = {
   0x38, 
   0x40, 
   0x80, 
   0xf8, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_36 = {0, 3, 6, 9, 7, ucrs_glyph_36, sizeof(ucrs_glyph_36)};

// Glyph 0x37: 7
const unsigned char ucrs_glyph_37[] = {
   0xfc, 
   0x04, 
   0x08, 
   0x08, 
   0x10, 
   0x10, 
   0x20, 
   0x20, 
   0x40, 
};
const dsd_glyph_info dss_glyph_info_37 = {0, 3, 6, 9, 7, ucrs_glyph_37, sizeof(ucrs_glyph_37)};

// Glyph 0x38: 8
const unsigned char ucrs_glyph_38[] = {
   0x78, 
   0x84, 
   0x84, 
   0x84, 
   0x78, 
   0x84, 
   0x84, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_38 = {0, 3, 6, 9, 7, ucrs_glyph_38, sizeof(ucrs_glyph_38)};

// Glyph 0x39: 9
const unsigned char ucrs_glyph_39[] = {
   0x78, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x7c, 
   0x04, 
   0x08, 
   0x70, 
};
const dsd_glyph_info dss_glyph_info_39 = {0, 3, 6, 9, 7, ucrs_glyph_39, sizeof(ucrs_glyph_39)};

// Glyph 0x3a: :
const unsigned char ucrs_glyph_3a[] = {
   0x80, 
   0x80, 
   0x00, 
   0x00, 
   0x00, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_3a = {1, 5, 1, 7, 4, ucrs_glyph_3a, sizeof(ucrs_glyph_3a)};

// Glyph 0x3b: ;
const unsigned char ucrs_glyph_3b[] = {
   0x40, 
   0x40, 
   0x00, 
   0x00, 
   0x00, 
   0x40, 
   0x40, 
   0x40, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_3b = {0, 5, 3, 9, 4, ucrs_glyph_3b, sizeof(ucrs_glyph_3b)};

// Glyph 0x3c: <
const unsigned char ucrs_glyph_3c[] = {
   0x04, 
   0x18, 
   0x60, 
   0x80, 
   0x60, 
   0x18, 
   0x04, 
};
const dsd_glyph_info dss_glyph_info_3c = {1, 5, 6, 7, 9, ucrs_glyph_3c, sizeof(ucrs_glyph_3c)};

// Glyph 0x3d: =
const unsigned char ucrs_glyph_3d[] = {
   0xfc, 
   0x00, 
   0xfc, 
};
const dsd_glyph_info dss_glyph_info_3d = {1, 6, 6, 3, 9, ucrs_glyph_3d, sizeof(ucrs_glyph_3d)};

// Glyph 0x3e: >
const unsigned char ucrs_glyph_3e[] = {
   0x80, 
   0x60, 
   0x18, 
   0x04, 
   0x18, 
   0x60, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_3e = {1, 5, 6, 7, 9, ucrs_glyph_3e, sizeof(ucrs_glyph_3e)};

// Glyph 0x3f: ?
const unsigned char ucrs_glyph_3f[] = {
   0x70, 
   0x88, 
   0x08, 
   0x08, 
   0x30, 
   0x40, 
   0x40, 
   0x00, 
   0x40, 
};
const dsd_glyph_info dss_glyph_info_3f = {0, 3, 5, 9, 6, ucrs_glyph_3f, sizeof(ucrs_glyph_3f)};

// Glyph 0x40: @
const unsigned char ucrs_glyph_40[] = {
   0x1e, 0x00, 
   0x61, 0x80, 
   0x5e, 0x80, 
   0xa2, 0x40, 
   0xa2, 0x40, 
   0xa2, 0x40, 
   0xa2, 0x40, 
   0x5f, 0x80, 
   0x60, 0x00, 
   0x1e, 0x00, 
};
const dsd_glyph_info dss_glyph_info_40 = {0, 3, 10, 10, 11, ucrs_glyph_40, sizeof(ucrs_glyph_40)};

// Glyph 0x41: A
const unsigned char ucrs_glyph_41[] = {
   0x10, 
   0x28, 
   0x28, 
   0x28, 
   0x44, 
   0x44, 
   0x7c, 
   0x82, 
   0x82, 
};
const dsd_glyph_info dss_glyph_info_41 = {0, 3, 7, 9, 8, ucrs_glyph_41, sizeof(ucrs_glyph_41)};

// Glyph 0x42: B
const unsigned char ucrs_glyph_42[] = {
   0xf8, 
   0x84, 
   0x84, 
   0x84, 
   0xf8, 
   0x84, 
   0x84, 
   0x84, 
   0xf8, 
};
const dsd_glyph_info dss_glyph_info_42 = {0, 3, 6, 9, 7, ucrs_glyph_42, sizeof(ucrs_glyph_42)};

// Glyph 0x43: C
const unsigned char ucrs_glyph_43[] = {
   0x3c, 
   0x40, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x40, 
   0x3c, 
};
const dsd_glyph_info dss_glyph_info_43 = {0, 3, 6, 9, 7, ucrs_glyph_43, sizeof(ucrs_glyph_43)};

// Glyph 0x44: D
const unsigned char ucrs_glyph_44[] = {
   0xf8, 
   0x84, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x84, 
   0xf8, 
};
const dsd_glyph_info dss_glyph_info_44 = {0, 3, 7, 9, 8, ucrs_glyph_44, sizeof(ucrs_glyph_44)};

// Glyph 0x45: E
const unsigned char ucrs_glyph_45[] = {
   0xfc, 
   0x80, 
   0x80, 
   0x80, 
   0xfc, 
   0x80, 
   0x80, 
   0x80, 
   0xfc, 
};
const dsd_glyph_info dss_glyph_info_45 = {0, 3, 6, 9, 7, ucrs_glyph_45, sizeof(ucrs_glyph_45)};

// Glyph 0x46: F
const unsigned char ucrs_glyph_46[] = {
   0xf8, 
   0x80, 
   0x80, 
   0x80, 
   0xf8, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_46 = {0, 3, 5, 9, 6, ucrs_glyph_46, sizeof(ucrs_glyph_46)};

// Glyph 0x47: G
const unsigned char ucrs_glyph_47[] = {
   0x3c, 
   0x42, 
   0x80, 
   0x80, 
   0x8e, 
   0x82, 
   0x82, 
   0x42, 
   0x3e, 
};
const dsd_glyph_info dss_glyph_info_47 = {0, 3, 7, 9, 8, ucrs_glyph_47, sizeof(ucrs_glyph_47)};

// Glyph 0x48: H
const unsigned char ucrs_glyph_48[] = {
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0xfe, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
};
const dsd_glyph_info dss_glyph_info_48 = {0, 3, 7, 9, 8, ucrs_glyph_48, sizeof(ucrs_glyph_48)};

// Glyph 0x49: I
const unsigned char ucrs_glyph_49[] = {
   0xe0, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_49 = {0, 3, 3, 9, 4, ucrs_glyph_49, sizeof(ucrs_glyph_49)};

// Glyph 0x4a: J
const unsigned char ucrs_glyph_4a[] = {
   0x70, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_4a = {0, 3, 4, 9, 5, ucrs_glyph_4a, sizeof(ucrs_glyph_4a)};

// Glyph 0x4b: K
const unsigned char ucrs_glyph_4b[] = {
   0x84, 
   0x88, 
   0x90, 
   0xa0, 
   0xc0, 
   0xa0, 
   0x90, 
   0x88, 
   0x84, 
};
const dsd_glyph_info dss_glyph_info_4b = {0, 3, 6, 9, 7, ucrs_glyph_4b, sizeof(ucrs_glyph_4b)};

// Glyph 0x4c: L
const unsigned char ucrs_glyph_4c[] = {
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0xf8, 
};
const dsd_glyph_info dss_glyph_info_4c = {0, 3, 5, 9, 6, ucrs_glyph_4c, sizeof(ucrs_glyph_4c)};

// Glyph 0x4d: M
const unsigned char ucrs_glyph_4d[] = {
   0xc3, 
   0xc3, 
   0xa5, 
   0xa5, 
   0xa5, 
   0x99, 
   0x99, 
   0x81, 
   0x81, 
};
const dsd_glyph_info dss_glyph_info_4d = {0, 3, 8, 9, 9, ucrs_glyph_4d, sizeof(ucrs_glyph_4d)};

// Glyph 0x4e: N
const unsigned char ucrs_glyph_4e[] = {
   0xc2, 
   0xc2, 
   0xa2, 
   0xa2, 
   0x92, 
   0x8a, 
   0x8a, 
   0x86, 
   0x86, 
};
const dsd_glyph_info dss_glyph_info_4e = {0, 3, 7, 9, 8, ucrs_glyph_4e, sizeof(ucrs_glyph_4e)};

// Glyph 0x4f: O
const unsigned char ucrs_glyph_4f[] = {
   0x3c, 
   0x42, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x42, 
   0x3c, 
};
const dsd_glyph_info dss_glyph_info_4f = {0, 3, 8, 9, 9, ucrs_glyph_4f, sizeof(ucrs_glyph_4f)};

// Glyph 0x50: P
const unsigned char ucrs_glyph_50[] = {
   0xf8, 
   0x84, 
   0x84, 
   0x84, 
   0x8c, 
   0xf0, 
   0x80, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_50 = {0, 3, 6, 9, 7, ucrs_glyph_50, sizeof(ucrs_glyph_50)};

// Glyph 0x51: Q
const unsigned char ucrs_glyph_51[] = {
   0x3c, 
   0x42, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x42, 
   0x3c, 
   0x08, 
   0x07, 
};
const dsd_glyph_info dss_glyph_info_51 = {0, 3, 8, 11, 9, ucrs_glyph_51, sizeof(ucrs_glyph_51)};

// Glyph 0x52: R
const unsigned char ucrs_glyph_52[] = {
   0xf0, 
   0x88, 
   0x88, 
   0x88, 
   0xf0, 
   0x90, 
   0x88, 
   0x88, 
   0x84, 
};
const dsd_glyph_info dss_glyph_info_52 = {0, 3, 6, 9, 7, ucrs_glyph_52, sizeof(ucrs_glyph_52)};

// Glyph 0x53: S
const unsigned char ucrs_glyph_53[] = {
   0x78, 
   0x84, 
   0x80, 
   0x80, 
   0x78, 
   0x04, 
   0x04, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_53 = {0, 3, 6, 9, 7, ucrs_glyph_53, sizeof(ucrs_glyph_53)};

// Glyph 0x54: T
const unsigned char ucrs_glyph_54[] = {
   0xfe, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
};
const dsd_glyph_info dss_glyph_info_54 = {0, 3, 7, 9, 8, ucrs_glyph_54, sizeof(ucrs_glyph_54)};

// Glyph 0x55: U
const unsigned char ucrs_glyph_55[] = {
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x44, 
   0x38, 
};
const dsd_glyph_info dss_glyph_info_55 = {0, 3, 7, 9, 8, ucrs_glyph_55, sizeof(ucrs_glyph_55)};

// Glyph 0x56: V
const unsigned char ucrs_glyph_56[] = {
   0x82, 
   0x82, 
   0x44, 
   0x44, 
   0x44, 
   0x28, 
   0x28, 
   0x28, 
   0x10, 
};
const dsd_glyph_info dss_glyph_info_56 = {0, 3, 7, 9, 8, ucrs_glyph_56, sizeof(ucrs_glyph_56)};

// Glyph 0x57: W
const unsigned char ucrs_glyph_57[] = {
   0x84, 0x20, 
   0x84, 0x20, 
   0x4a, 0x40, 
   0x4a, 0x40, 
   0x4a, 0x40, 
   0x51, 0x40, 
   0x31, 0x80, 
   0x20, 0x80, 
   0x20, 0x80, 
};
const dsd_glyph_info dss_glyph_info_57 = {0, 3, 11, 9, 12, ucrs_glyph_57, sizeof(ucrs_glyph_57)};

// Glyph 0x58: X
const unsigned char ucrs_glyph_58[] = {
   0x84, 
   0x48, 
   0x48, 
   0x30, 
   0x30, 
   0x30, 
   0x48, 
   0x48, 
   0x84, 
};
const dsd_glyph_info dss_glyph_info_58 = {0, 3, 6, 9, 7, ucrs_glyph_58, sizeof(ucrs_glyph_58)};

// Glyph 0x59: Y
const unsigned char ucrs_glyph_59[] = {
   0x82, 
   0x44, 
   0x44, 
   0x28, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
};
const dsd_glyph_info dss_glyph_info_59 = {0, 3, 7, 9, 8, ucrs_glyph_59, sizeof(ucrs_glyph_59)};

// Glyph 0x5a: Z
const unsigned char ucrs_glyph_5a[] = {
   0xfc, 
   0x04, 
   0x08, 
   0x10, 
   0x20, 
   0x20, 
   0x40, 
   0x80, 
   0xfc, 
};
const dsd_glyph_info dss_glyph_info_5a = {0, 3, 6, 9, 7, ucrs_glyph_5a, sizeof(ucrs_glyph_5a)};

// Glyph 0x5b: [
const unsigned char ucrs_glyph_5b[] = {
   0xe0, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_5b = {1, 2, 3, 12, 5, ucrs_glyph_5b, sizeof(ucrs_glyph_5b)};

// Glyph 0x5c: '\'
const unsigned char ucrs_glyph_5c[] = {
   0x80, 
   0x80, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x10, 
   0x10, 
};
const dsd_glyph_info dss_glyph_info_5c = {0, 2, 4, 12, 5, ucrs_glyph_5c, sizeof(ucrs_glyph_5c)};

// Glyph 0x5d: ]
const unsigned char ucrs_glyph_5d[] = {
   0xe0, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_5d = {1, 2, 3, 12, 5, ucrs_glyph_5d, sizeof(ucrs_glyph_5d)};

// Glyph 0x5e: ^
const unsigned char ucrs_glyph_5e[] = {
   0x10, 
   0x28, 
   0x44, 
   0x82, 
};
const dsd_glyph_info dss_glyph_info_5e = {1, 3, 7, 4, 9, ucrs_glyph_5e, sizeof(ucrs_glyph_5e)};

// Glyph 0x5f: _
const unsigned char ucrs_glyph_5f[] = {
   0xfe, 
};
const dsd_glyph_info dss_glyph_info_5f = {0, 13, 7, 1, 7, ucrs_glyph_5f, sizeof(ucrs_glyph_5f)};

// Glyph 0x60: `
const unsigned char ucrs_glyph_60[] = {
   0x80, 
   0x40, 
};
const dsd_glyph_info dss_glyph_info_60 = {1, 2, 2, 2, 7, ucrs_glyph_60, sizeof(ucrs_glyph_60)};

// Glyph 0x61: a
const unsigned char ucrs_glyph_61[] = {
   0x70, 
   0x08, 
   0x08, 
   0x78, 
   0x88, 
   0x88, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_61 = {0, 5, 5, 7, 6, ucrs_glyph_61, sizeof(ucrs_glyph_61)};

// Glyph 0x62: b
const unsigned char ucrs_glyph_62[] = {
   0x80, 
   0x80, 
   0x80, 
   0xb8, 
   0xc4, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0xf8, 
};
const dsd_glyph_info dss_glyph_info_62 = {0, 2, 6, 10, 7, ucrs_glyph_62, sizeof(ucrs_glyph_62)};

// Glyph 0x63: c
const unsigned char ucrs_glyph_63[] = {
   0x78, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_63 = {0, 5, 5, 7, 6, ucrs_glyph_63, sizeof(ucrs_glyph_63)};

// Glyph 0x64: d
const unsigned char ucrs_glyph_64[] = {
   0x04, 
   0x04, 
   0x04, 
   0x7c, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x8c, 
   0x74, 
};
const dsd_glyph_info dss_glyph_info_64 = {0, 2, 6, 10, 7, ucrs_glyph_64, sizeof(ucrs_glyph_64)};

// Glyph 0x65: e
const unsigned char ucrs_glyph_65[] = {
   0x78, 
   0x84, 
   0x84, 
   0xfc, 
   0x80, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_65 = {0, 5, 6, 7, 7, ucrs_glyph_65, sizeof(ucrs_glyph_65)};

// Glyph 0x66: f
const unsigned char ucrs_glyph_66[] = {
   0x30, 
   0x40, 
   0x40, 
   0xf0, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
};
const dsd_glyph_info dss_glyph_info_66 = {0, 2, 4, 10, 4, ucrs_glyph_66, sizeof(ucrs_glyph_66)};

// Glyph 0x67: g
const unsigned char ucrs_glyph_67[] = {
   0x7c, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x8c, 
   0x74, 
   0x04, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_67 = {0, 5, 6, 9, 7, ucrs_glyph_67, sizeof(ucrs_glyph_67)};

// Glyph 0x68: h
const unsigned char ucrs_glyph_68[] = {
   0x80, 
   0x80, 
   0x80, 
   0xb8, 
   0xc4, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
};
const dsd_glyph_info dss_glyph_info_68 = {0, 2, 6, 10, 7, ucrs_glyph_68, sizeof(ucrs_glyph_68)};

// Glyph 0x69: i
const unsigned char ucrs_glyph_69[] = {
   0x80, 
   0x00, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_69 = {0, 3, 1, 9, 2, ucrs_glyph_69, sizeof(ucrs_glyph_69)};

// Glyph 0x6a: j
const unsigned char ucrs_glyph_6a[] = {
   0x20, 
   0x00, 
   0x60, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0xc0, 
};
const dsd_glyph_info dss_glyph_info_6a = {-1, 3, 3, 11, 3, ucrs_glyph_6a, sizeof(ucrs_glyph_6a)};

// Glyph 0x6b: k
const unsigned char ucrs_glyph_6b[] = {
   0x80, 
   0x80, 
   0x80, 
   0x88, 
   0x90, 
   0xa0, 
   0xc0, 
   0xa0, 
   0x90, 
   0x88, 
};
const dsd_glyph_info dss_glyph_info_6b = {0, 2, 6, 10, 6, ucrs_glyph_6b, sizeof(ucrs_glyph_6b)};

// Glyph 0x6c: l
const unsigned char ucrs_glyph_6c[] = {
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_6c = {0, 2, 1, 10, 2, ucrs_glyph_6c, sizeof(ucrs_glyph_6c)};

// Glyph 0x6d: m
const unsigned char ucrs_glyph_6d[] = {
   0xf7, 0x00, 
   0x88, 0x80, 
   0x88, 0x80, 
   0x88, 0x80, 
   0x88, 0x80, 
   0x88, 0x80, 
   0x88, 0x80, 
};
const dsd_glyph_info dss_glyph_info_6d = {0, 5, 9, 7, 10, ucrs_glyph_6d, sizeof(ucrs_glyph_6d)};

// Glyph 0x6e: n
const unsigned char ucrs_glyph_6e[] = {
   0xb8, 
   0xc4, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
};
const dsd_glyph_info dss_glyph_info_6e = {0, 5, 6, 7, 7, ucrs_glyph_6e, sizeof(ucrs_glyph_6e)};

// Glyph 0x6f: o
const unsigned char ucrs_glyph_6f[] = {
   0x78, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_6f = {0, 5, 6, 7, 7, ucrs_glyph_6f, sizeof(ucrs_glyph_6f)};

// Glyph 0x70: p
const unsigned char ucrs_glyph_70[] = {
   0xb8, 
   0xc4, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0xf8, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_70 = {0, 5, 6, 9, 7, ucrs_glyph_70, sizeof(ucrs_glyph_70)};

// Glyph 0x71: q
const unsigned char ucrs_glyph_71[] = {
   0x7c, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x8c, 
   0x74, 
   0x04, 
   0x04, 
};
const dsd_glyph_info dss_glyph_info_71 = {0, 5, 6, 9, 7, ucrs_glyph_71, sizeof(ucrs_glyph_71)};

// Glyph 0x72: r
const unsigned char ucrs_glyph_72[] = {
   0xa0, 
   0xc0, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_72 = {0, 5, 3, 7, 4, ucrs_glyph_72, sizeof(ucrs_glyph_72)};

// Glyph 0x73: s
const unsigned char ucrs_glyph_73[] = {
   0x70, 
   0x80, 
   0x80, 
   0x60, 
   0x10, 
   0x10, 
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_73 = {0, 5, 4, 7, 5, ucrs_glyph_73, sizeof(ucrs_glyph_73)};

// Glyph 0x74: t
const unsigned char ucrs_glyph_74[] = {
   0x40, 
   0x40, 
   0xf0, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x30, 
};
const dsd_glyph_info dss_glyph_info_74 = {0, 3, 4, 9, 5, ucrs_glyph_74, sizeof(ucrs_glyph_74)};

// Glyph 0x75: u
const unsigned char ucrs_glyph_75[] = {
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x8c, 
   0x74, 
};
const dsd_glyph_info dss_glyph_info_75 = {0, 5, 6, 7, 7, ucrs_glyph_75, sizeof(ucrs_glyph_75)};

// Glyph 0x76: v
const unsigned char ucrs_glyph_76[] = {
   0x88, 
   0x88, 
   0x50, 
   0x50, 
   0x50, 
   0x20, 
   0x20, 
};
const dsd_glyph_info dss_glyph_info_76 = {0, 5, 5, 7, 6, ucrs_glyph_76, sizeof(ucrs_glyph_76)};

// Glyph 0x77: w
const unsigned char ucrs_glyph_77[] = {
   0x88, 0x80, 
   0x88, 0x80, 
   0x55, 0x00, 
   0x55, 0x00, 
   0x55, 0x00, 
   0x22, 0x00, 
   0x22, 0x00, 
};
const dsd_glyph_info dss_glyph_info_77 = {0, 5, 9, 7, 10, ucrs_glyph_77, sizeof(ucrs_glyph_77)};

// Glyph 0x78: x
const unsigned char ucrs_glyph_78[] = {
   0x88, 
   0x50, 
   0x50, 
   0x20, 
   0x50, 
   0x50, 
   0x88, 
};
const dsd_glyph_info dss_glyph_info_78 = {0, 5, 5, 7, 6, ucrs_glyph_78, sizeof(ucrs_glyph_78)};

// Glyph 0x79: y
const unsigned char ucrs_glyph_79[] = {
   0x88, 
   0x88, 
   0x50, 
   0x50, 
   0x50, 
   0x20, 
   0x20, 
   0x20, 
   0x40, 
};
const dsd_glyph_info dss_glyph_info_79 = {0, 5, 5, 9, 6, ucrs_glyph_79, sizeof(ucrs_glyph_79)};

// Glyph 0x7a: z
const unsigned char ucrs_glyph_7a[] = {
   0xf0, 
   0x10, 
   0x20, 
   0x40, 
   0x40, 
   0x80, 
   0xf0, 
};
const dsd_glyph_info dss_glyph_info_7a = {0, 5, 4, 7, 5, ucrs_glyph_7a, sizeof(ucrs_glyph_7a)};

// Glyph 0x7b: {
const unsigned char ucrs_glyph_7b[] = {
   0x18, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0xc0, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x18, 
};
const dsd_glyph_info dss_glyph_info_7b = {0, 2, 5, 12, 6, ucrs_glyph_7b, sizeof(ucrs_glyph_7b)};

// Glyph 0x7c: |
const unsigned char ucrs_glyph_7c[] = {
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_7c = {2, 2, 1, 12, 5, ucrs_glyph_7c, sizeof(ucrs_glyph_7c)};

// Glyph 0x7d: }
const unsigned char ucrs_glyph_7d[] = {
   0xc0, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0x18, 
   0x20, 
   0x20, 
   0x20, 
   0x20, 
   0xc0, 
};
const dsd_glyph_info dss_glyph_info_7d = {0, 2, 5, 12, 6, ucrs_glyph_7d, sizeof(ucrs_glyph_7d)};

// Glyph 0x7e: ~
const unsigned char ucrs_glyph_7e[] = {
   0x62, 
   0x92, 
   0x8c, 
};
const dsd_glyph_info dss_glyph_info_7e = {1, 7, 7, 3, 9, ucrs_glyph_7e, sizeof(ucrs_glyph_7e)};

// Glyph 0x7f: 
const unsigned char ucrs_glyph_7f[] = {
   0xff, 0x80, 
   0x80, 0x80, 
   0x80, 0x80, 
   0x80, 0x80, 
   0x80, 0x80, 
   0x80, 0x80, 
   0x80, 0x80, 
   0x80, 0x80, 
   0xff, 0x80, 
};
const dsd_glyph_info dss_glyph_info_7f = {2, 3, 9, 9, 12, ucrs_glyph_7f, sizeof(ucrs_glyph_7f)};

// Glyph 0xa0:  
const unsigned char ucrs_glyph_a0[] = { 0 };
const dsd_glyph_info dss_glyph_info_a0 = {0, 12, 0, 0, 4, ucrs_glyph_a0, 0};

// Glyph 0xa1: ¡
const unsigned char ucrs_glyph_a1[] = {
   0x80, 
   0x00, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_a1 = {1, 3, 1, 9, 4, ucrs_glyph_a1, sizeof(ucrs_glyph_a1)};

// Glyph 0xa2: ¢
const unsigned char ucrs_glyph_a2[] = {
   0x20, 
   0x20, 
   0x78, 
   0xa0, 
   0xa0, 
   0xa0, 
   0xa0, 
   0xa0, 
   0x78, 
   0x20, 
   0x20, 
};
const dsd_glyph_info dss_glyph_info_a2 = {1, 3, 5, 11, 7, ucrs_glyph_a2, sizeof(ucrs_glyph_a2)};

// Glyph 0xa3: £
const unsigned char ucrs_glyph_a3[] = {
   0x3c, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0xf8, 
   0x40, 
   0x40, 
   0xfc, 
};
const dsd_glyph_info dss_glyph_info_a3 = {0, 3, 6, 9, 7, ucrs_glyph_a3, sizeof(ucrs_glyph_a3)};

// Glyph 0xa4: ¤
const unsigned char ucrs_glyph_a4[] = {
   0x84, 
   0x78, 
   0x48, 
   0x48, 
   0x78, 
   0x84, 
};
const dsd_glyph_info dss_glyph_info_a4 = {0, 5, 6, 6, 7, ucrs_glyph_a4, sizeof(ucrs_glyph_a4)};

// Glyph 0xa5: ¥
const unsigned char ucrs_glyph_a5[] = {
   0x82, 
   0x44, 
   0x28, 
   0x28, 
   0x10, 
   0x7c, 
   0x10, 
   0x10, 
   0x10, 
};
const dsd_glyph_info dss_glyph_info_a5 = {0, 3, 7, 9, 7, ucrs_glyph_a5, sizeof(ucrs_glyph_a5)};

// Glyph 0xa6: ¦
const unsigned char ucrs_glyph_a6[] = {
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x00, 
   0x00, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_a6 = {2, 2, 1, 12, 5, ucrs_glyph_a6, sizeof(ucrs_glyph_a6)};

// Glyph 0xa7: §
const unsigned char ucrs_glyph_a7[] = {
   0x78, 
   0x80, 
   0x80, 
   0x60, 
   0x90, 
   0x88, 
   0x48, 
   0x30, 
   0x08, 
   0x88, 
   0xf0, 
};
const dsd_glyph_info dss_glyph_info_a7 = {1, 3, 5, 11, 7, ucrs_glyph_a7, sizeof(ucrs_glyph_a7)};

// Glyph 0xa8: ¨
const unsigned char ucrs_glyph_a8[] = {
   0x90, 
};
const dsd_glyph_info dss_glyph_info_a8 = {1, 3, 4, 1, 7, ucrs_glyph_a8, sizeof(ucrs_glyph_a8)};

// Glyph 0xa9: ©
const unsigned char ucrs_glyph_a9[] = {
   0x1e, 0x00, 
   0x61, 0x80, 
   0x4c, 0x80, 
   0x92, 0x40, 
   0x90, 0x40, 
   0x90, 0x40, 
   0x92, 0x40, 
   0x4c, 0x80, 
   0x61, 0x80, 
   0x1e, 0x00, 
};
const dsd_glyph_info dss_glyph_info_a9 = {0, 3, 10, 10, 11, ucrs_glyph_a9, sizeof(ucrs_glyph_a9)};

// Glyph 0xaa: ª
const unsigned char ucrs_glyph_aa[] = {
   0xe0, 
   0x10, 
   0x70, 
   0x90, 
   0x90, 
   0x70, 
};
const dsd_glyph_info dss_glyph_info_aa = {1, 3, 4, 6, 6, ucrs_glyph_aa, sizeof(ucrs_glyph_aa)};

// Glyph 0xab: «
const unsigned char ucrs_glyph_ab[] = {
   0x24, 
   0x48, 
   0x90, 
   0x90, 
   0x48, 
   0x24, 
};
const dsd_glyph_info dss_glyph_info_ab = {0, 5, 6, 6, 7, ucrs_glyph_ab, sizeof(ucrs_glyph_ab)};

// Glyph 0xac: ¬
const unsigned char ucrs_glyph_ac[] = {
   0xfe, 
   0x02, 
   0x02, 
   0x02, 
};
const dsd_glyph_info dss_glyph_info_ac = {1, 8, 7, 4, 9, ucrs_glyph_ac, sizeof(ucrs_glyph_ac)};

// Glyph 0xad: ­
const unsigned char ucrs_glyph_ad[] = {
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_ad = {0, 8, 3, 1, 4, ucrs_glyph_ad, sizeof(ucrs_glyph_ad)};

// Glyph 0xae: ®
const unsigned char ucrs_glyph_ae[] = {
   0x1e, 0x00, 
   0x61, 0x80, 
   0x5c, 0x80, 
   0x92, 0x40, 
   0x92, 0x40, 
   0x9c, 0x40, 
   0x92, 0x40, 
   0x51, 0x80, 
   0x61, 0x80, 
   0x1e, 0x00, 
};
const dsd_glyph_info dss_glyph_info_ae = {0, 3, 10, 10, 11, ucrs_glyph_ae, sizeof(ucrs_glyph_ae)};

// Glyph 0xaf: ¯
const unsigned char ucrs_glyph_af[] = {
   0xfe, 
};
const dsd_glyph_info dss_glyph_info_af = {0, 2, 7, 1, 7, ucrs_glyph_af, sizeof(ucrs_glyph_af)};

// Glyph 0xb0: °
const unsigned char ucrs_glyph_b0[] = {
   0x60, 
   0x90, 
   0x90, 
   0x60, 
};
const dsd_glyph_info dss_glyph_info_b0 = {1, 3, 4, 4, 6, ucrs_glyph_b0, sizeof(ucrs_glyph_b0)};

// Glyph 0xb1: ±
const unsigned char ucrs_glyph_b1[] = {
   0x10, 
   0x10, 
   0x10, 
   0xfe, 
   0x10, 
   0x10, 
   0xfe, 
};
const dsd_glyph_info dss_glyph_info_b1 = {0, 4, 7, 7, 8, ucrs_glyph_b1, sizeof(ucrs_glyph_b1)};

// Glyph 0xb2: ²
const unsigned char ucrs_glyph_b2[] = {
   0xe0, 
   0x10, 
   0x30, 
   0x40, 
   0xf0, 
};
const dsd_glyph_info dss_glyph_info_b2 = {1, 3, 4, 5, 6, ucrs_glyph_b2, sizeof(ucrs_glyph_b2)};

// Glyph 0xb3: ³
const unsigned char ucrs_glyph_b3[] = {
   0xe0, 
   0x10, 
   0x60, 
   0x10, 
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_b3 = {1, 3, 4, 5, 6, ucrs_glyph_b3, sizeof(ucrs_glyph_b3)};

// Glyph 0xb4: ´
const unsigned char ucrs_glyph_b4[] = {
   0x40, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_b4 = {3, 2, 2, 2, 7, ucrs_glyph_b4, sizeof(ucrs_glyph_b4)};

// Glyph 0xb5: µ
const unsigned char ucrs_glyph_b5[] = {
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x8c, 
   0xf4, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_b5 = {0, 5, 6, 9, 7, ucrs_glyph_b5, sizeof(ucrs_glyph_b5)};

// Glyph 0xb6: ¶
const unsigned char ucrs_glyph_b6[] = {
   0x7c, 
   0xf4, 
   0xf4, 
   0xf4, 
   0x74, 
   0x14, 
   0x14, 
   0x14, 
   0x14, 
   0x14, 
   0x14, 
};
const dsd_glyph_info dss_glyph_info_b6 = {0, 3, 6, 11, 7, ucrs_glyph_b6, sizeof(ucrs_glyph_b6)};

// Glyph 0xb7: ·
const unsigned char ucrs_glyph_b7[] = {
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_b7 = {1, 5, 1, 2, 4, ucrs_glyph_b7, sizeof(ucrs_glyph_b7)};

// Glyph 0xb8: ¸
const unsigned char ucrs_glyph_b8[] = {
   0x20, 
   0xc0, 
};
const dsd_glyph_info dss_glyph_info_b8 = {2, 12, 3, 2, 7, ucrs_glyph_b8, sizeof(ucrs_glyph_b8)};

// Glyph 0xb9: ¹
const unsigned char ucrs_glyph_b9[] = {
   0x40, 
   0xc0, 
   0x40, 
   0x40, 
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_b9 = {2, 3, 3, 5, 6, ucrs_glyph_b9, sizeof(ucrs_glyph_b9)};

// Glyph 0xba: º
const unsigned char ucrs_glyph_ba[] = {
   0x70, 
   0x88, 
   0x88, 
   0x88, 
   0x88, 
   0x70, 
};
const dsd_glyph_info dss_glyph_info_ba = {0, 3, 5, 6, 6, ucrs_glyph_ba, sizeof(ucrs_glyph_ba)};

// Glyph 0xbb: »
const unsigned char ucrs_glyph_bb[] = {
   0x90, 
   0x48, 
   0x24, 
   0x24, 
   0x48, 
   0x90, 
};
const dsd_glyph_info dss_glyph_info_bb = {0, 5, 6, 6, 7, ucrs_glyph_bb, sizeof(ucrs_glyph_bb)};

// Glyph 0xbc: ¼
const unsigned char ucrs_glyph_bc[] = {
   0x42, 0x00, 
   0xc4, 0x00, 
   0x44, 0x00, 
   0x48, 0x00, 
   0x49, 0x80, 
   0x12, 0x80, 
   0x24, 0x80, 
   0x27, 0xc0, 
   0x40, 0x80, 
};
const dsd_glyph_info dss_glyph_info_bc = {1, 3, 10, 9, 12, ucrs_glyph_bc, sizeof(ucrs_glyph_bc)};

// Glyph 0xbd: ½
const unsigned char ucrs_glyph_bd[] = {
   0x42, 0x00, 
   0xc2, 0x00, 
   0x44, 0x00, 
   0x44, 0x00, 
   0x4b, 0x80, 
   0x08, 0x40, 
   0x10, 0x80, 
   0x11, 0x00, 
   0x23, 0xc0, 
};
const dsd_glyph_info dss_glyph_info_bd = {1, 3, 10, 9, 12, ucrs_glyph_bd, sizeof(ucrs_glyph_bd)};

// Glyph 0xbe: ¾
const unsigned char ucrs_glyph_be[] = {
   0xe1, 0x00, 
   0x12, 0x00, 
   0x62, 0x00, 
   0x14, 0x00, 
   0x14, 0xc0, 
   0xe9, 0x40, 
   0x12, 0x40, 
   0x13, 0xe0, 
   0x20, 0x40, 
};
const dsd_glyph_info dss_glyph_info_be = {1, 3, 11, 9, 12, ucrs_glyph_be, sizeof(ucrs_glyph_be)};

// Glyph 0xbf: ¿
const unsigned char ucrs_glyph_bf[] = {
   0x10, 
   0x00, 
   0x10, 
   0x10, 
   0x20, 
   0x40, 
   0x80, 
   0x80, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_bf = {0, 3, 5, 9, 6, ucrs_glyph_bf, sizeof(ucrs_glyph_bf)};

// Glyph 0xc0: À
const unsigned char ucrs_glyph_c0[] = {
   0x20, 
   0x10, 
   0x00, 
   0x10, 
   0x28, 
   0x28, 
   0x28, 
   0x44, 
   0x44, 
   0x7c, 
   0x82, 
   0x82, 
};
const dsd_glyph_info dss_glyph_info_c0 = {0, 0, 7, 12, 8, ucrs_glyph_c0, sizeof(ucrs_glyph_c0)};

// Glyph 0xc1: Á
const unsigned char ucrs_glyph_c1[] = {
   0x08, 
   0x10, 
   0x00, 
   0x10, 
   0x28, 
   0x28, 
   0x28, 
   0x44, 
   0x44, 
   0x7c, 
   0x82, 
   0x82, 
};
const dsd_glyph_info dss_glyph_info_c1 = {0, 0, 7, 12, 8, ucrs_glyph_c1, sizeof(ucrs_glyph_c1)};

// Glyph 0xc2: Â
const unsigned char ucrs_glyph_c2[] = {
   0x18, 
   0x24, 
   0x00, 
   0x10, 
   0x28, 
   0x28, 
   0x28, 
   0x44, 
   0x44, 
   0x7c, 
   0x82, 
   0x82, 
};
const dsd_glyph_info dss_glyph_info_c2 = {0, 0, 7, 12, 8, ucrs_glyph_c2, sizeof(ucrs_glyph_c2)};

// Glyph 0xc3: Ã
const unsigned char ucrs_glyph_c3[] = {
   0x34, 
   0x58, 
   0x00, 
   0x10, 
   0x28, 
   0x28, 
   0x28, 
   0x44, 
   0x44, 
   0x7c, 
   0x82, 
   0x82, 
};
const dsd_glyph_info dss_glyph_info_c3 = {0, 0, 7, 12, 8, ucrs_glyph_c3, sizeof(ucrs_glyph_c3)};

// Glyph 0xc4: Ä
const unsigned char ucrs_glyph_c4[] = {
   0x44, 
   0x00, 
   0x10, 
   0x28, 
   0x28, 
   0x28, 
   0x44, 
   0x44, 
   0x7c, 
   0x82, 
   0x82, 
};
const dsd_glyph_info dss_glyph_info_c4 = {0, 1, 7, 11, 8, ucrs_glyph_c4, sizeof(ucrs_glyph_c4)};

// Glyph 0xc5: Å
const unsigned char ucrs_glyph_c5[] = {
   0x10, 
   0x28, 
   0x28, 
   0x10, 
   0x28, 
   0x28, 
   0x28, 
   0x44, 
   0x44, 
   0x7c, 
   0x82, 
   0x82, 
};
const dsd_glyph_info dss_glyph_info_c5 = {0, 0, 7, 12, 8, ucrs_glyph_c5, sizeof(ucrs_glyph_c5)};

// Glyph 0xc6: Æ
const unsigned char ucrs_glyph_c6[] = {
   0x1f, 0xc0, 
   0x14, 0x00, 
   0x24, 0x00, 
   0x24, 0x00, 
   0x27, 0xc0, 
   0x7c, 0x00, 
   0x44, 0x00, 
   0x44, 0x00, 
   0x87, 0xc0, 
};
const dsd_glyph_info dss_glyph_info_c6 = {0, 3, 10, 9, 11, ucrs_glyph_c6, sizeof(ucrs_glyph_c6)};

// Glyph 0xc7: Ç
const unsigned char ucrs_glyph_c7[] = {
   0x3c, 
   0x40, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x40, 
   0x3c, 
   0x08, 
   0x30, 
};
const dsd_glyph_info dss_glyph_info_c7 = {0, 3, 6, 11, 7, ucrs_glyph_c7, sizeof(ucrs_glyph_c7)};

// Glyph 0xc8: È
const unsigned char ucrs_glyph_c8[] = {
   0x20, 
   0x10, 
   0x00, 
   0xfc, 
   0x80, 
   0x80, 
   0x80, 
   0xfc, 
   0x80, 
   0x80, 
   0x80, 
   0xfc, 
};
const dsd_glyph_info dss_glyph_info_c8 = {0, 0, 6, 12, 7, ucrs_glyph_c8, sizeof(ucrs_glyph_c8)};

// Glyph 0xc9: É
const unsigned char ucrs_glyph_c9[] = {
   0x08, 
   0x10, 
   0x00, 
   0xfc, 
   0x80, 
   0x80, 
   0x80, 
   0xfc, 
   0x80, 
   0x80, 
   0x80, 
   0xfc, 
};
const dsd_glyph_info dss_glyph_info_c9 = {0, 0, 6, 12, 7, ucrs_glyph_c9, sizeof(ucrs_glyph_c9)};

// Glyph 0xca: Ê
const unsigned char ucrs_glyph_ca[] = {
   0x30, 
   0x48, 
   0x00, 
   0xfc, 
   0x80, 
   0x80, 
   0x80, 
   0xfc, 
   0x80, 
   0x80, 
   0x80, 
   0xfc, 
};
const dsd_glyph_info dss_glyph_info_ca = {0, 0, 6, 12, 7, ucrs_glyph_ca, sizeof(ucrs_glyph_ca)};

// Glyph 0xcb: Ë
const unsigned char ucrs_glyph_cb[] = {
   0x48, 
   0x00, 
   0xfc, 
   0x80, 
   0x80, 
   0x80, 
   0xfc, 
   0x80, 
   0x80, 
   0x80, 
   0xfc, 
};
const dsd_glyph_info dss_glyph_info_cb = {0, 1, 6, 11, 7, ucrs_glyph_cb, sizeof(ucrs_glyph_cb)};

// Glyph 0xcc: Ì
const unsigned char ucrs_glyph_cc[] = {
   0x80, 
   0x40, 
   0x00, 
   0xe0, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_cc = {0, 0, 3, 12, 4, ucrs_glyph_cc, sizeof(ucrs_glyph_cc)};

// Glyph 0xcd: Í
const unsigned char ucrs_glyph_cd[] = {
   0x20, 
   0x40, 
   0x00, 
   0xe0, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_cd = {0, 0, 3, 12, 4, ucrs_glyph_cd, sizeof(ucrs_glyph_cd)};

// Glyph 0xce: Î
const unsigned char ucrs_glyph_ce[] = {
   0x60, 
   0x90, 
   0x00, 
   0xe0, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_ce = {0, 0, 4, 12, 4, ucrs_glyph_ce, sizeof(ucrs_glyph_ce)};

// Glyph 0xcf: Ï
const unsigned char ucrs_glyph_cf[] = {
   0xa0, 
   0x00, 
   0xe0, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0xe0, 
};
const dsd_glyph_info dss_glyph_info_cf = {0, 1, 3, 11, 4, ucrs_glyph_cf, sizeof(ucrs_glyph_cf)};

// Glyph 0xd0: Ð
const unsigned char ucrs_glyph_d0[] = {
   0x78, 
   0x44, 
   0x42, 
   0x42, 
   0xf2, 
   0x42, 
   0x42, 
   0x44, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_d0 = {0, 3, 7, 9, 8, ucrs_glyph_d0, sizeof(ucrs_glyph_d0)};

// Glyph 0xd1: Ñ
const unsigned char ucrs_glyph_d1[] = {
   0x34, 
   0x58, 
   0x00, 
   0xc2, 
   0xc2, 
   0xa2, 
   0xa2, 
   0x92, 
   0x8a, 
   0x8a, 
   0x86, 
   0x86, 
};
const dsd_glyph_info dss_glyph_info_d1 = {0, 0, 7, 12, 8, ucrs_glyph_d1, sizeof(ucrs_glyph_d1)};

// Glyph 0xd2: Ò
const unsigned char ucrs_glyph_d2[] = {
   0x10, 
   0x08, 
   0x00, 
   0x3c, 
   0x42, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x42, 
   0x3c, 
};
const dsd_glyph_info dss_glyph_info_d2 = {0, 0, 8, 12, 9, ucrs_glyph_d2, sizeof(ucrs_glyph_d2)};

// Glyph 0xd3: Ó
const unsigned char ucrs_glyph_d3[] = {
   0x08, 
   0x10, 
   0x00, 
   0x3c, 
   0x42, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x42, 
   0x3c, 
};
const dsd_glyph_info dss_glyph_info_d3 = {0, 0, 8, 12, 9, ucrs_glyph_d3, sizeof(ucrs_glyph_d3)};

// Glyph 0xd4: Ô
const unsigned char ucrs_glyph_d4[] = {
   0x18, 
   0x24, 
   0x00, 
   0x3c, 
   0x42, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x42, 
   0x3c, 
};
const dsd_glyph_info dss_glyph_info_d4 = {0, 0, 8, 12, 9, ucrs_glyph_d4, sizeof(ucrs_glyph_d4)};

// Glyph 0xd5: Õ
const unsigned char ucrs_glyph_d5[] = {
   0x1a, 
   0x2c, 
   0x00, 
   0x3c, 
   0x42, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x42, 
   0x3c, 
};
const dsd_glyph_info dss_glyph_info_d5 = {0, 0, 8, 12, 9, ucrs_glyph_d5, sizeof(ucrs_glyph_d5)};

// Glyph 0xd6: Ö
const unsigned char ucrs_glyph_d6[] = {
   0x24, 
   0x00, 
   0x3c, 
   0x42, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x81, 
   0x42, 
   0x3c, 
};
const dsd_glyph_info dss_glyph_info_d6 = {0, 1, 8, 11, 9, ucrs_glyph_d6, sizeof(ucrs_glyph_d6)};

// Glyph 0xd7: ×
const unsigned char ucrs_glyph_d7[] = {
   0x00, 
   0x44, 
   0x28, 
   0x10, 
   0x28, 
   0x44, 
   0x00, 
};
const dsd_glyph_info dss_glyph_info_d7 = {1, 5, 7, 7, 9, ucrs_glyph_d7, sizeof(ucrs_glyph_d7)};

// Glyph 0xd8: Ø
const unsigned char ucrs_glyph_d8[] = {
   0x3d, 
   0x42, 
   0x85, 
   0x89, 
   0x91, 
   0x91, 
   0xa1, 
   0x42, 
   0x7c, 
   0x00, 
};
const dsd_glyph_info dss_glyph_info_d8 = {0, 3, 8, 10, 9, ucrs_glyph_d8, sizeof(ucrs_glyph_d8)};

// Glyph 0xd9: Ù
const unsigned char ucrs_glyph_d9[] = {
   0x20, 
   0x10, 
   0x00, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x44, 
   0x38, 
};
const dsd_glyph_info dss_glyph_info_d9 = {0, 0, 7, 12, 8, ucrs_glyph_d9, sizeof(ucrs_glyph_d9)};

// Glyph 0xda: Ú
const unsigned char ucrs_glyph_da[] = {
   0x08, 
   0x10, 
   0x00, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x44, 
   0x38, 
};
const dsd_glyph_info dss_glyph_info_da = {0, 0, 7, 12, 8, ucrs_glyph_da, sizeof(ucrs_glyph_da)};

// Glyph 0xdb: Û
const unsigned char ucrs_glyph_db[] = {
   0x18, 
   0x24, 
   0x00, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x44, 
   0x38, 
};
const dsd_glyph_info dss_glyph_info_db = {0, 0, 7, 12, 8, ucrs_glyph_db, sizeof(ucrs_glyph_db)};

// Glyph 0xdc: Ü
const unsigned char ucrs_glyph_dc[] = {
   0x44, 
   0x00, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x82, 
   0x44, 
   0x38, 
};
const dsd_glyph_info dss_glyph_info_dc = {0, 1, 7, 11, 8, ucrs_glyph_dc, sizeof(ucrs_glyph_dc)};

// Glyph 0xdd: Ý
const unsigned char ucrs_glyph_dd[] = {
   0x08, 
   0x10, 
   0x00, 
   0x82, 
   0x44, 
   0x44, 
   0x28, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
   0x10, 
};
const dsd_glyph_info dss_glyph_info_dd = {0, 0, 7, 12, 8, ucrs_glyph_dd, sizeof(ucrs_glyph_dd)};

// Glyph 0xde: Þ
const unsigned char ucrs_glyph_de[] = {
   0x80, 
   0x80, 
   0xf8, 
   0x84, 
   0x84, 
   0x84, 
   0xf8, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_de = {0, 3, 6, 9, 7, ucrs_glyph_de, sizeof(ucrs_glyph_de)};

// Glyph 0xdf: ß
const unsigned char ucrs_glyph_df[] = {
   0x70, 
   0x88, 
   0x88, 
   0x88, 
   0xb0, 
   0x88, 
   0x84, 
   0x84, 
   0x88, 
   0xb0, 
};
const dsd_glyph_info dss_glyph_info_df = {0, 2, 6, 10, 7, ucrs_glyph_df, sizeof(ucrs_glyph_df)};

// Glyph 0xe0: à
const unsigned char ucrs_glyph_e0[] = {
   0x20, 
   0x10, 
   0x00, 
   0x70, 
   0x08, 
   0x08, 
   0x78, 
   0x88, 
   0x88, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_e0 = {0, 2, 5, 10, 6, ucrs_glyph_e0, sizeof(ucrs_glyph_e0)};

// Glyph 0xe1: á
const unsigned char ucrs_glyph_e1[] = {
   0x10, 
   0x20, 
   0x00, 
   0x70, 
   0x08, 
   0x08, 
   0x78, 
   0x88, 
   0x88, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_e1 = {0, 2, 5, 10, 6, ucrs_glyph_e1, sizeof(ucrs_glyph_e1)};

// Glyph 0xe2: â
const unsigned char ucrs_glyph_e2[] = {
   0x30, 
   0x48, 
   0x00, 
   0x70, 
   0x08, 
   0x08, 
   0x78, 
   0x88, 
   0x88, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_e2 = {0, 2, 5, 10, 6, ucrs_glyph_e2, sizeof(ucrs_glyph_e2)};

// Glyph 0xe3: ã
const unsigned char ucrs_glyph_e3[] = {
   0x68, 
   0xb0, 
   0x00, 
   0x70, 
   0x08, 
   0x08, 
   0x78, 
   0x88, 
   0x88, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_e3 = {0, 2, 5, 10, 6, ucrs_glyph_e3, sizeof(ucrs_glyph_e3)};

// Glyph 0xe4: ä
const unsigned char ucrs_glyph_e4[] = {
   0x48, 
   0x00, 
   0x70, 
   0x08, 
   0x08, 
   0x78, 
   0x88, 
   0x88, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_e4 = {0, 3, 5, 9, 6, ucrs_glyph_e4, sizeof(ucrs_glyph_e4)};

// Glyph 0xe5: å
const unsigned char ucrs_glyph_e5[] = {
   0x30, 
   0x48, 
   0x48, 
   0x30, 
   0x70, 
   0x08, 
   0x08, 
   0x78, 
   0x88, 
   0x88, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_e5 = {0, 1, 5, 11, 6, ucrs_glyph_e5, sizeof(ucrs_glyph_e5)};

// Glyph 0xe6: æ
const unsigned char ucrs_glyph_e6[] = {
   0x73, 0x00, 
   0x0c, 0x80, 
   0x08, 0x40, 
   0x7f, 0xc0, 
   0x88, 0x00, 
   0x8c, 0x40, 
   0x73, 0x80, 
};
const dsd_glyph_info dss_glyph_info_e6 = {0, 5, 10, 7, 11, ucrs_glyph_e6, sizeof(ucrs_glyph_e6)};

// Glyph 0xe7: ç
const unsigned char ucrs_glyph_e7[] = {
   0x78, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x78, 
   0x10, 
   0x60, 
};
const dsd_glyph_info dss_glyph_info_e7 = {0, 5, 5, 9, 6, ucrs_glyph_e7, sizeof(ucrs_glyph_e7)};

// Glyph 0xe8: è
const unsigned char ucrs_glyph_e8[] = {
   0x20, 
   0x10, 
   0x00, 
   0x78, 
   0x84, 
   0x84, 
   0xfc, 
   0x80, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_e8 = {0, 2, 6, 10, 7, ucrs_glyph_e8, sizeof(ucrs_glyph_e8)};

// Glyph 0xe9: é
const unsigned char ucrs_glyph_e9[] = {
   0x10, 
   0x20, 
   0x00, 
   0x78, 
   0x84, 
   0x84, 
   0xfc, 
   0x80, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_e9 = {0, 2, 6, 10, 7, ucrs_glyph_e9, sizeof(ucrs_glyph_e9)};

// Glyph 0xea: ê
const unsigned char ucrs_glyph_ea[] = {
   0x30, 
   0x48, 
   0x00, 
   0x78, 
   0x84, 
   0x84, 
   0xfc, 
   0x80, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_ea = {0, 2, 6, 10, 7, ucrs_glyph_ea, sizeof(ucrs_glyph_ea)};

// Glyph 0xeb: ë
const unsigned char ucrs_glyph_eb[] = {
   0x48, 
   0x00, 
   0x78, 
   0x84, 
   0x84, 
   0xfc, 
   0x80, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_eb = {0, 3, 6, 9, 7, ucrs_glyph_eb, sizeof(ucrs_glyph_eb)};

// Glyph 0xec: ì
const unsigned char ucrs_glyph_ec[] = {
   0x80, 
   0x40, 
   0x00, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
};
const dsd_glyph_info dss_glyph_info_ec = {-1, 2, 2, 10, 2, ucrs_glyph_ec, sizeof(ucrs_glyph_ec)};

// Glyph 0xed: í
const unsigned char ucrs_glyph_ed[] = {
   0x40, 
   0x80, 
   0x00, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_ed = {0, 2, 2, 10, 2, ucrs_glyph_ed, sizeof(ucrs_glyph_ed)};

// Glyph 0xee: î
const unsigned char ucrs_glyph_ee[] = {
   0x40, 
   0xa0, 
   0x00, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
};
const dsd_glyph_info dss_glyph_info_ee = {-1, 2, 3, 10, 2, ucrs_glyph_ee, sizeof(ucrs_glyph_ee)};

// Glyph 0xef: ï
const unsigned char ucrs_glyph_ef[] = {
   0xa0, 
   0x00, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
   0x40, 
};
const dsd_glyph_info dss_glyph_info_ef = {-1, 3, 3, 9, 2, ucrs_glyph_ef, sizeof(ucrs_glyph_ef)};

// Glyph 0xf0: ð
const unsigned char ucrs_glyph_f0[] = {
   0x28, 
   0x10, 
   0x68, 
   0x04, 
   0x7c, 
   0x84, 
   0x84, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_f0 = {0, 3, 6, 9, 7, ucrs_glyph_f0, sizeof(ucrs_glyph_f0)};

// Glyph 0xf1: ñ
const unsigned char ucrs_glyph_f1[] = {
   0x34, 
   0x58, 
   0x00, 
   0xb8, 
   0xc4, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
};
const dsd_glyph_info dss_glyph_info_f1 = {0, 2, 6, 10, 7, ucrs_glyph_f1, sizeof(ucrs_glyph_f1)};

// Glyph 0xf2: ò
const unsigned char ucrs_glyph_f2[] = {
   0x40, 
   0x20, 
   0x00, 
   0x78, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_f2 = {0, 2, 6, 10, 7, ucrs_glyph_f2, sizeof(ucrs_glyph_f2)};

// Glyph 0xf3: ó
const unsigned char ucrs_glyph_f3[] = {
   0x08, 
   0x10, 
   0x00, 
   0x78, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_f3 = {0, 2, 6, 10, 7, ucrs_glyph_f3, sizeof(ucrs_glyph_f3)};

// Glyph 0xf4: ô
const unsigned char ucrs_glyph_f4[] = {
   0x30, 
   0x48, 
   0x00, 
   0x78, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_f4 = {0, 2, 6, 10, 7, ucrs_glyph_f4, sizeof(ucrs_glyph_f4)};

// Glyph 0xf5: õ
const unsigned char ucrs_glyph_f5[] = {
   0x34, 
   0x58, 
   0x00, 
   0x78, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_f5 = {0, 2, 6, 10, 7, ucrs_glyph_f5, sizeof(ucrs_glyph_f5)};

// Glyph 0xf6: ö
const unsigned char ucrs_glyph_f6[] = {
   0x48, 
   0x00, 
   0x78, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x78, 
};
const dsd_glyph_info dss_glyph_info_f6 = {0, 3, 6, 9, 7, ucrs_glyph_f6, sizeof(ucrs_glyph_f6)};

// Glyph 0xf7: ÷
const unsigned char ucrs_glyph_f7[] = {
   0x10, 
   0x10, 
   0x00, 
   0xfe, 
   0x00, 
   0x10, 
   0x10, 
};
const dsd_glyph_info dss_glyph_info_f7 = {1, 5, 7, 7, 9, ucrs_glyph_f7, sizeof(ucrs_glyph_f7)};

// Glyph 0xf8: ø
const unsigned char ucrs_glyph_f8[] = {
   0x02, 
   0x3c, 
   0x44, 
   0x8a, 
   0x92, 
   0xa2, 
   0x44, 
   0x78, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_f8 = {0, 4, 7, 9, 8, ucrs_glyph_f8, sizeof(ucrs_glyph_f8)};

// Glyph 0xf9: ù
const unsigned char ucrs_glyph_f9[] = {
   0x20, 
   0x10, 
   0x00, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x8c, 
   0x74, 
};
const dsd_glyph_info dss_glyph_info_f9 = {0, 2, 6, 10, 7, ucrs_glyph_f9, sizeof(ucrs_glyph_f9)};

// Glyph 0xfa: ú
const unsigned char ucrs_glyph_fa[] = {
   0x08, 
   0x10, 
   0x00, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x8c, 
   0x74, 
};
const dsd_glyph_info dss_glyph_info_fa = {0, 2, 6, 10, 7, ucrs_glyph_fa, sizeof(ucrs_glyph_fa)};

// Glyph 0xfb: û
const unsigned char ucrs_glyph_fb[] = {
   0x30, 
   0x48, 
   0x00, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x8c, 
   0x74, 
};
const dsd_glyph_info dss_glyph_info_fb = {0, 2, 6, 10, 7, ucrs_glyph_fb, sizeof(ucrs_glyph_fb)};

// Glyph 0xfc: ü
const unsigned char ucrs_glyph_fc[] = {
   0x48, 
   0x00, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0x8c, 
   0x74, 
};
const dsd_glyph_info dss_glyph_info_fc = {0, 3, 6, 9, 7, ucrs_glyph_fc, sizeof(ucrs_glyph_fc)};

// Glyph 0xfd: ý
const unsigned char ucrs_glyph_fd[] = {
   0x10, 
   0x20, 
   0x00, 
   0x88, 
   0x88, 
   0x50, 
   0x50, 
   0x50, 
   0x20, 
   0x20, 
   0x20, 
   0x40, 
};
const dsd_glyph_info dss_glyph_info_fd = {0, 2, 5, 12, 6, ucrs_glyph_fd, sizeof(ucrs_glyph_fd)};

// Glyph 0xfe: þ
const unsigned char ucrs_glyph_fe[] = {
   0x80, 
   0x80, 
   0x80, 
   0xb8, 
   0xc4, 
   0x84, 
   0x84, 
   0x84, 
   0x84, 
   0xf8, 
   0x80, 
   0x80, 
};
const dsd_glyph_info dss_glyph_info_fe = {0, 2, 6, 12, 7, ucrs_glyph_fe, sizeof(ucrs_glyph_fe)};

// Glyph 0xff: ÿ
const unsigned char ucrs_glyph_ff[] = {
   0x48, 
   0x00, 
   0x88, 
   0x88, 
   0x50, 
   0x50, 
   0x50, 
   0x20, 
   0x20, 
   0x20, 
   0x40, 
};
const dsd_glyph_info dss_glyph_info_ff = {0, 3, 5, 11, 6, ucrs_glyph_ff, sizeof(ucrs_glyph_ff)};

const dsd_glyph_info* adsr_glyphs[] = {
   &dss_glyph_info_20, // 0x00
   &dss_glyph_info_20, // 0x01
   &dss_glyph_info_20, // 0x02
   &dss_glyph_info_20, // 0x03
   &dss_glyph_info_20, // 0x04
   &dss_glyph_info_20, // 0x05
   &dss_glyph_info_20, // 0x06
   &dss_glyph_info_20, // 0x07
   &dss_glyph_info_20, // 0x08
   &dss_glyph_info_20, // 0x09
   &dss_glyph_info_20, // 0x0a
   &dss_glyph_info_20, // 0x0b
   &dss_glyph_info_20, // 0x0c
   &dss_glyph_info_20, // 0x0d
   &dss_glyph_info_20, // 0x0e
   &dss_glyph_info_20, // 0x0f
   &dss_glyph_info_20, // 0x10
   &dss_glyph_info_20, // 0x11
   &dss_glyph_info_20, // 0x12
   &dss_glyph_info_20, // 0x13
   &dss_glyph_info_20, // 0x14
   &dss_glyph_info_20, // 0x15
   &dss_glyph_info_20, // 0x16
   &dss_glyph_info_20, // 0x17
   &dss_glyph_info_20, // 0x18
   &dss_glyph_info_20, // 0x19
   &dss_glyph_info_20, // 0x1a
   &dss_glyph_info_20, // 0x1b
   &dss_glyph_info_20, // 0x1c
   &dss_glyph_info_20, // 0x1d
   &dss_glyph_info_20, // 0x1e
   &dss_glyph_info_20, // 0x1f
   &dss_glyph_info_20, //  
   &dss_glyph_info_21, // !
   &dss_glyph_info_22, // "
   &dss_glyph_info_23, // #
   &dss_glyph_info_24, // $
   &dss_glyph_info_25, // %
   &dss_glyph_info_26, // &
   &dss_glyph_info_27, // '
   &dss_glyph_info_28, // (
   &dss_glyph_info_29, // )
   &dss_glyph_info_2a, // *
   &dss_glyph_info_2b, // +
   &dss_glyph_info_2c, // ,
   &dss_glyph_info_2d, // -
   &dss_glyph_info_2e, // .
   &dss_glyph_info_2f, // /
   &dss_glyph_info_30, // 0
   &dss_glyph_info_31, // 1
   &dss_glyph_info_32, // 2
   &dss_glyph_info_33, // 3
   &dss_glyph_info_34, // 4
   &dss_glyph_info_35, // 5
   &dss_glyph_info_36, // 6
   &dss_glyph_info_37, // 7
   &dss_glyph_info_38, // 8
   &dss_glyph_info_39, // 9
   &dss_glyph_info_3a, // :
   &dss_glyph_info_3b, // ;
   &dss_glyph_info_3c, // <
   &dss_glyph_info_3d, // =
   &dss_glyph_info_3e, // >
   &dss_glyph_info_3f, // ?
   &dss_glyph_info_40, // @
   &dss_glyph_info_41, // A
   &dss_glyph_info_42, // B
   &dss_glyph_info_43, // C
   &dss_glyph_info_44, // D
   &dss_glyph_info_45, // E
   &dss_glyph_info_46, // F
   &dss_glyph_info_47, // G
   &dss_glyph_info_48, // H
   &dss_glyph_info_49, // I
   &dss_glyph_info_4a, // J
   &dss_glyph_info_4b, // K
   &dss_glyph_info_4c, // L
   &dss_glyph_info_4d, // M
   &dss_glyph_info_4e, // N
   &dss_glyph_info_4f, // O
   &dss_glyph_info_50, // P
   &dss_glyph_info_51, // Q
   &dss_glyph_info_52, // R
   &dss_glyph_info_53, // S
   &dss_glyph_info_54, // T
   &dss_glyph_info_55, // U
   &dss_glyph_info_56, // V
   &dss_glyph_info_57, // W
   &dss_glyph_info_58, // X
   &dss_glyph_info_59, // Y
   &dss_glyph_info_5a, // Z
   &dss_glyph_info_5b, // [
   &dss_glyph_info_5c, // '\'
   &dss_glyph_info_5d, // ]
   &dss_glyph_info_5e, // ^
   &dss_glyph_info_5f, // _
   &dss_glyph_info_60, // `
   &dss_glyph_info_61, // a
   &dss_glyph_info_62, // b
   &dss_glyph_info_63, // c
   &dss_glyph_info_64, // d
   &dss_glyph_info_65, // e
   &dss_glyph_info_66, // f
   &dss_glyph_info_67, // g
   &dss_glyph_info_68, // h
   &dss_glyph_info_69, // i
   &dss_glyph_info_6a, // j
   &dss_glyph_info_6b, // k
   &dss_glyph_info_6c, // l
   &dss_glyph_info_6d, // m
   &dss_glyph_info_6e, // n
   &dss_glyph_info_6f, // o
   &dss_glyph_info_70, // p
   &dss_glyph_info_71, // q
   &dss_glyph_info_72, // r
   &dss_glyph_info_73, // s
   &dss_glyph_info_74, // t
   &dss_glyph_info_75, // u
   &dss_glyph_info_76, // v
   &dss_glyph_info_77, // w
   &dss_glyph_info_78, // x
   &dss_glyph_info_79, // y
   &dss_glyph_info_7a, // z
   &dss_glyph_info_7b, // {
   &dss_glyph_info_7c, // |
   &dss_glyph_info_7d, // }
   &dss_glyph_info_7e, // ~
   &dss_glyph_info_7f, // 
   &dss_glyph_info_20, // 0x80
   &dss_glyph_info_20, // 0x81
   &dss_glyph_info_20, // 0x82
   &dss_glyph_info_20, // 0x83
   &dss_glyph_info_20, // 0x84
   &dss_glyph_info_20, // 0x85
   &dss_glyph_info_20, // 0x86
   &dss_glyph_info_20, // 0x87
   &dss_glyph_info_20, // 0x88
   &dss_glyph_info_20, // 0x89
   &dss_glyph_info_20, // 0x8a
   &dss_glyph_info_20, // 0x8b
   &dss_glyph_info_20, // 0x8c
   &dss_glyph_info_20, // 0x8d
   &dss_glyph_info_20, // 0x8e
   &dss_glyph_info_20, // 0x8f
   &dss_glyph_info_20, // 0x90
   &dss_glyph_info_20, // 0x91
   &dss_glyph_info_20, // 0x92
   &dss_glyph_info_20, // 0x93
   &dss_glyph_info_20, // 0x94
   &dss_glyph_info_20, // 0x95
   &dss_glyph_info_20, // 0x96
   &dss_glyph_info_20, // 0x97
   &dss_glyph_info_20, // 0x98
   &dss_glyph_info_20, // 0x99
   &dss_glyph_info_20, // 0x9a
   &dss_glyph_info_20, // 0x9b
   &dss_glyph_info_20, // 0x9c
   &dss_glyph_info_20, // 0x9d
   &dss_glyph_info_20, // 0x9e
   &dss_glyph_info_20, // 0x9f
   &dss_glyph_info_a0, //  
   &dss_glyph_info_a1, // ¡
   &dss_glyph_info_a2, // ¢
   &dss_glyph_info_a3, // £
   &dss_glyph_info_a4, // ¤
   &dss_glyph_info_a5, // ¥
   &dss_glyph_info_a6, // ¦
   &dss_glyph_info_a7, // §
   &dss_glyph_info_a8, // ¨
   &dss_glyph_info_a9, // ©
   &dss_glyph_info_aa, // ª
   &dss_glyph_info_ab, // «
   &dss_glyph_info_ac, // ¬
   &dss_glyph_info_ad, // ­
   &dss_glyph_info_ae, // ®
   &dss_glyph_info_af, // ¯
   &dss_glyph_info_b0, // °
   &dss_glyph_info_b1, // ±
   &dss_glyph_info_b2, // ²
   &dss_glyph_info_b3, // ³
   &dss_glyph_info_b4, // ´
   &dss_glyph_info_b5, // µ
   &dss_glyph_info_b6, // ¶
   &dss_glyph_info_b7, // ·
   &dss_glyph_info_b8, // ¸
   &dss_glyph_info_b9, // ¹
   &dss_glyph_info_ba, // º
   &dss_glyph_info_bb, // »
   &dss_glyph_info_bc, // ¼
   &dss_glyph_info_bd, // ½
   &dss_glyph_info_be, // ¾
   &dss_glyph_info_bf, // ¿
   &dss_glyph_info_c0, // À
   &dss_glyph_info_c1, // Á
   &dss_glyph_info_c2, // Â
   &dss_glyph_info_c3, // Ã
   &dss_glyph_info_c4, // Ä
   &dss_glyph_info_c5, // Å
   &dss_glyph_info_c6, // Æ
   &dss_glyph_info_c7, // Ç
   &dss_glyph_info_c8, // È
   &dss_glyph_info_c9, // É
   &dss_glyph_info_ca, // Ê
   &dss_glyph_info_cb, // Ë
   &dss_glyph_info_cc, // Ì
   &dss_glyph_info_cd, // Í
   &dss_glyph_info_ce, // Î
   &dss_glyph_info_cf, // Ï
   &dss_glyph_info_d0, // Ð
   &dss_glyph_info_d1, // Ñ
   &dss_glyph_info_d2, // Ò
   &dss_glyph_info_d3, // Ó
   &dss_glyph_info_d4, // Ô
   &dss_glyph_info_d5, // Õ
   &dss_glyph_info_d6, // Ö
   &dss_glyph_info_d7, // ×
   &dss_glyph_info_d8, // Ø
   &dss_glyph_info_d9, // Ù
   &dss_glyph_info_da, // Ú
   &dss_glyph_info_db, // Û
   &dss_glyph_info_dc, // Ü
   &dss_glyph_info_dd, // Ý
   &dss_glyph_info_de, // Þ
   &dss_glyph_info_df, // ß
   &dss_glyph_info_e0, // à
   &dss_glyph_info_e1, // á
   &dss_glyph_info_e2, // â
   &dss_glyph_info_e3, // ã
   &dss_glyph_info_e4, // ä
   &dss_glyph_info_e5, // å
   &dss_glyph_info_e6, // æ
   &dss_glyph_info_e7, // ç
   &dss_glyph_info_e8, // è
   &dss_glyph_info_e9, // é
   &dss_glyph_info_ea, // ê
   &dss_glyph_info_eb, // ë
   &dss_glyph_info_ec, // ì
   &dss_glyph_info_ed, // í
   &dss_glyph_info_ee, // î
   &dss_glyph_info_ef, // ï
   &dss_glyph_info_f0, // ð
   &dss_glyph_info_f1, // ñ
   &dss_glyph_info_f2, // ò
   &dss_glyph_info_f3, // ó
   &dss_glyph_info_f4, // ô
   &dss_glyph_info_f5, // õ
   &dss_glyph_info_f6, // ö
   &dss_glyph_info_f7, // ÷
   &dss_glyph_info_f8, // ø
   &dss_glyph_info_f9, // ù
   &dss_glyph_info_fa, // ú
   &dss_glyph_info_fb, // û
   &dss_glyph_info_fc, // ü
   &dss_glyph_info_fd, // ý
   &dss_glyph_info_fe, // þ
   &dss_glyph_info_ff, // ÿ
};




static dsd_glyph* amc_getglyphpattern_tahoma(void* ap_userfld, void* avop_usrfld_getstorglyph, struct dsd_font* dsl_font, int inl_glyph, amd_cr_getstorglyph aml_cr_getstorglyph){
   if((inl_glyph > 0xff) || (inl_glyph < 0))
      inl_glyph = 0x7f;

   // Get glyphinfo from array;
   const dsd_glyph_info* ads_glyph_info = adsr_glyphs[inl_glyph];

   // Get memory
   dsd_glyph* dsl_g = (dsd_glyph*) aml_cr_getstorglyph(avop_usrfld_getstorglyph, ads_glyph_info->inc_len_pattern); 

   // Copy infos
   dsl_g->usc_x        = ads_glyph_info->isc_x;
   dsl_g->usc_y        = ads_glyph_info->isc_y;
   dsl_g->usc_cx       = ads_glyph_info->usc_cx;
   dsl_g->usc_cy       = ads_glyph_info->usc_cy;
   dsl_g->usc_distance = ads_glyph_info->usc_distance;
   memcpy(dsl_g + 1, ads_glyph_info->ucc_pattern, ads_glyph_info->inc_len_pattern);

   // Return glyph
   return dsl_g;
}


#endif