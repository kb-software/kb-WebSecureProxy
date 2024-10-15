#ifndef HOB_DATARW
#define HOB_DATARW

#if 0
#include <cstdint>
#endif
#include <stdint.h>

#ifndef HL_LOCAL_SCOPE
#define HL_LOCAL_SCOPE extern inline
#endif

// Static Read Functions

// 16 bit
HL_LOCAL_SCOPE uint16_t m_read_uint16_le(unsigned char* aucp_data) {
	return ((*(aucp_data + 0) <<  0) & 0x00ff) | 
		((*(aucp_data + 1) <<  8) & 0xff00);
}
HL_LOCAL_SCOPE uint16_t m_read_uint16_be(unsigned char* aucp_data) {
	return ((*(aucp_data + 0) <<  8) & 0xff00) | 
		((*(aucp_data + 1) <<  0) & 0x00ff);
}
HL_LOCAL_SCOPE int16_t m_read_int16_le(unsigned char* aucp_data) {
	return ((*(aucp_data + 0) <<  0) & 0x00ff) | 
		((*(aucp_data + 1) <<  8) & 0xff00);
}
HL_LOCAL_SCOPE int16_t m_read_int16_be(unsigned char* aucp_data) {
	return ((*(aucp_data + 0) <<  8) & 0xff00) | 
		((*(aucp_data + 1) <<  0) & 0x00ff);
}

// 24 bit
HL_LOCAL_SCOPE unsigned int m_read_uint24_le(unsigned char* aucp_data){
	return ((*(aucp_data + 0) <<  0) & 0x0000ff) | 
		((*(aucp_data + 1) <<  8) & 0x00ff00) | 
		((*(aucp_data + 2) << 16) & 0xff0000);
}
HL_LOCAL_SCOPE unsigned int m_read_uint24_be(unsigned char* aucp_data){
	return ((*(aucp_data + 0) << 16) & 0xff0000) | 
		((*(aucp_data + 1) <<  8) & 0x00ff00) | 
		((*(aucp_data + 2) <<  0) & 0x0000ff);
}
HL_LOCAL_SCOPE signed int m_read_int24_le(unsigned char* aucp_data){
	return ((signed int)(((*(aucp_data + 0) <<  8) & 0x0000ff00) | 
		((*(aucp_data + 1) << 16) & 0x00ff0000) | 
		((*(aucp_data + 2) << 24) & 0xff000000))) >> 8;
}
HL_LOCAL_SCOPE signed int m_read_int24_be(unsigned char* aucp_data){
	return ((signed int)(((*(aucp_data + 0) << 24) & 0xff000000) | 
		((*(aucp_data + 1) << 16) & 0x00ff0000) | 
		((*(aucp_data + 2) <<  8) & 0x0000ff00))) >> 8;
}

// 32 bit
HL_LOCAL_SCOPE uint32_t m_read_uint32_le(unsigned char* aucp_data) {
	return ((*(aucp_data + 0) <<  0) & 0x000000ff) | 
		((*(aucp_data + 1) <<  8) & 0x0000ff00) |
		((*(aucp_data + 2) << 16) & 0x00ff0000) |
		((*(aucp_data + 3) << 24) & 0xff000000);
}
HL_LOCAL_SCOPE uint32_t m_read_uint32_be(unsigned char* aucp_data) {
	return ((*(aucp_data + 0) << 24) & 0xff000000) | 
		((*(aucp_data + 1) << 16) & 0x00ff0000) |
		((*(aucp_data + 2) <<  8) & 0x0000ff00) |
		((*(aucp_data + 3) <<  0) & 0x000000ff);
}
HL_LOCAL_SCOPE int32_t m_read_int32_le(unsigned char* aucp_data) {
	return ((*(aucp_data + 0) <<  0) & 0x000000ff) | 
		((*(aucp_data + 1) <<  8) & 0x0000ff00) |
		((*(aucp_data + 2) << 16) & 0x00ff0000) |
		((*(aucp_data + 3) << 24) & 0xff000000);
}
HL_LOCAL_SCOPE int32_t m_read_int32_be(unsigned char* aucp_data) {
	return ((*(aucp_data + 0) << 24) & 0xff000000) | 
		((*(aucp_data + 1) << 16) & 0x00ff0000) |
		((*(aucp_data + 2) <<  8) & 0x0000ff00) |
		((*(aucp_data + 3) <<  0) & 0x000000ff);
}

HL_LOCAL_SCOPE char *m_read_hasn1_sint32_be(char* aucp_data, char* aucp_data_end, signed int *alp_val){
	long ill_val = 0;
	while(aucp_data < aucp_data_end) {
		char chl_tmp = (*aucp_data++);
		if(chl_tmp >= 0) {
			*alp_val = (ill_val << 7) | chl_tmp;
			goto signify;
		}
		ill_val <<= 7;
		ill_val |= (chl_tmp & 0x7f);
	}
	return 0;
signify:
	if((*alp_val & 0x1) == 0)
		*alp_val >>= 1;
	else
		*alp_val = ~(*alp_val >> 1);

	return aucp_data;
}


// Static Write Functions

// 16 bit
HL_LOCAL_SCOPE void m_write_uint16_le(unsigned char* aucp_mem, uint16_t usp_value){
	*(aucp_mem++) = (unsigned char)  usp_value;
	*(aucp_mem++) = (unsigned char) (usp_value >> 8);
}
HL_LOCAL_SCOPE void m_write_uint16_be(unsigned char* aucp_mem, uint16_t usp_value){
	*(aucp_mem++) = (unsigned char) (usp_value >> 8);
	*(aucp_mem++) = (unsigned char)  usp_value;
}
HL_LOCAL_SCOPE void m_write_int16_le(unsigned char* aucp_mem, int16_t isp_value){
	*(aucp_mem++) = (unsigned char)  isp_value;
	*(aucp_mem++) = (unsigned char) (isp_value >> 8);
}
HL_LOCAL_SCOPE void m_write_int16_be(unsigned char* aucp_mem, int16_t isp_value){
	*(aucp_mem++) = (unsigned char) (isp_value >> 8);
	*(aucp_mem++) = (unsigned char)  isp_value;
}

HL_LOCAL_SCOPE unsigned char* m_safe_write_uint16_le(unsigned char* aucp_mem, unsigned char* aucp_mem_end, uint16_t usp_value){
	if (aucp_mem + 2 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char)  usp_value;
	*(aucp_mem++) = (unsigned char) (usp_value >> 8);
	return aucp_mem;
}
HL_LOCAL_SCOPE unsigned char* m_safe_write_uint16_be(unsigned char* aucp_mem, unsigned char* aucp_mem_end, uint16_t usp_value){
	if (aucp_mem + 2 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char) (usp_value >> 8);
	*(aucp_mem++) = (unsigned char)  usp_value;
	return aucp_mem;
}
HL_LOCAL_SCOPE unsigned char* m_safe_write_int16_le(unsigned char* aucp_mem, unsigned char* aucp_mem_end, int16_t isp_value){
	if (aucp_mem + 2 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char)  isp_value;
	*(aucp_mem++) = (unsigned char) (isp_value >> 8);
	return aucp_mem;
}
HL_LOCAL_SCOPE unsigned char* m_safe_write_int16_be(unsigned char* aucp_mem, unsigned char* aucp_mem_end, int16_t isp_value){
	if (aucp_mem + 2 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char) (isp_value >> 8);
	*(aucp_mem++) = (unsigned char)  isp_value;
	return aucp_mem;
}

// 24 bit
HL_LOCAL_SCOPE void m_write_uint24_le(unsigned char* aucp_mem, unsigned int ump_value){
	*(aucp_mem++) = (unsigned char)  ump_value;
	*(aucp_mem++) = (unsigned char) (ump_value >>  8);
	*(aucp_mem++) = (unsigned char) (ump_value >> 16);
}
HL_LOCAL_SCOPE void m_write_uint24_be(unsigned char* aucp_mem, unsigned int ump_value){
	*(aucp_mem++) = (unsigned char) (ump_value >> 16);
	*(aucp_mem++) = (unsigned char) (ump_value >>  8);
	*(aucp_mem++) = (unsigned char)  ump_value;
}
HL_LOCAL_SCOPE void m_write_int24_le(unsigned char* aucp_mem, signed int ilp_value){
	*(aucp_mem++) = (unsigned char)  ilp_value;
	*(aucp_mem++) = (unsigned char) (ilp_value >>  8);
	*(aucp_mem++) = (unsigned char) (ilp_value >> 16);
}
HL_LOCAL_SCOPE void m_write_int24_be(unsigned char* aucp_mem, signed int ilp_value){
	*(aucp_mem++) = (unsigned char) (ilp_value >> 16);
	*(aucp_mem++) = (unsigned char) (ilp_value >>  8);
	*(aucp_mem++) = (unsigned char)  ilp_value;
}

HL_LOCAL_SCOPE unsigned char*  m_safe_write_uint24_le(unsigned char* aucp_mem, unsigned char* aucp_mem_end, unsigned int ump_value){
	if (aucp_mem + 3 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char)  ump_value;
	*(aucp_mem++) = (unsigned char) (ump_value >>  8);
	*(aucp_mem++) = (unsigned char) (ump_value >> 16);
	return aucp_mem;
}
HL_LOCAL_SCOPE unsigned char*  m_safe_write_uint24_be(unsigned char* aucp_mem, unsigned char* aucp_mem_end, unsigned int ump_value){
	if (aucp_mem + 3 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char) (ump_value >> 16);
	*(aucp_mem++) = (unsigned char) (ump_value >>  8);
	*(aucp_mem++) = (unsigned char)  ump_value;
	return aucp_mem;
}
HL_LOCAL_SCOPE unsigned char*  m_safe_write_int24_le(unsigned char* aucp_mem, unsigned char* aucp_mem_end, signed int ilp_value){
	if (aucp_mem + 3 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char)  ilp_value;
	*(aucp_mem++) = (unsigned char) (ilp_value >>  8);
	*(aucp_mem++) = (unsigned char) (ilp_value >> 16);
	return aucp_mem;
}
HL_LOCAL_SCOPE unsigned char*  m_safe_write_int24_be(unsigned char* aucp_mem, unsigned char* aucp_mem_end, signed int ilp_value){
	if (aucp_mem + 3 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char) (ilp_value >> 16);
	*(aucp_mem++) = (unsigned char) (ilp_value >>  8);
	*(aucp_mem++) = (unsigned char)  ilp_value;
	return aucp_mem;
}

// 32 bit
HL_LOCAL_SCOPE void m_write_uint32_le(unsigned char* aucp_mem, uint32_t ump_value) {
	*(aucp_mem++) = (unsigned char)  ump_value;
	*(aucp_mem++) = (unsigned char) (ump_value >>  8);
	*(aucp_mem++) = (unsigned char) (ump_value >> 16);
	*(aucp_mem++) = (unsigned char) (ump_value >> 24);
}
HL_LOCAL_SCOPE void m_write_uint32_be(unsigned char* aucp_mem, uint32_t ump_value) {
	*(aucp_mem++) = (unsigned char) (ump_value >> 24);
	*(aucp_mem++) = (unsigned char) (ump_value >> 16);
	*(aucp_mem++) = (unsigned char) (ump_value >>  8);
	*(aucp_mem++) = (unsigned char)  ump_value;
}
HL_LOCAL_SCOPE void m_write_int32_le(unsigned char* aucp_mem, int32_t ilp_value) {
	*(aucp_mem++) = (unsigned char)  ilp_value;
	*(aucp_mem++) = (unsigned char) (ilp_value >>  8);
	*(aucp_mem++) = (unsigned char) (ilp_value >> 16);
	*(aucp_mem++) = (unsigned char) (ilp_value >> 24);
}
HL_LOCAL_SCOPE void m_write_int32_be(unsigned char* aucp_mem, int32_t ilp_value) {
	*(aucp_mem++) = (unsigned char) (ilp_value >> 24);
	*(aucp_mem++) = (unsigned char) (ilp_value >> 16);
	*(aucp_mem++) = (unsigned char) (ilp_value >>  8);
	*(aucp_mem++) = (unsigned char)  ilp_value;
}

HL_LOCAL_SCOPE unsigned char* m_safe_write_uint32_le(unsigned char* aucp_mem, unsigned char* aucp_mem_end, uint32_t ump_value) {
	if (aucp_mem + 4 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char)  ump_value;
	*(aucp_mem++) = (unsigned char) (ump_value >>  8);
	*(aucp_mem++) = (unsigned char) (ump_value >> 16);
	*(aucp_mem++) = (unsigned char) (ump_value >> 24);
	return aucp_mem;
}

HL_LOCAL_SCOPE unsigned char* m_safe_write_uint32_be(unsigned char* aucp_mem, unsigned char* aucp_mem_end, uint32_t ump_value) {
	if (aucp_mem + 4 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char) (ump_value >> 24);
	*(aucp_mem++) = (unsigned char) (ump_value >> 16);
	*(aucp_mem++) = (unsigned char) (ump_value >>  8);
	*(aucp_mem++) = (unsigned char)  ump_value;
	return aucp_mem;
}

HL_LOCAL_SCOPE unsigned char* m_safe_write_int32_le(unsigned char* aucp_mem, unsigned char* aucp_mem_end, int32_t imp_value) {
	if (aucp_mem + 4 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char)  imp_value;
	*(aucp_mem++) = (unsigned char) (imp_value >>  8);
	*(aucp_mem++) = (unsigned char) (imp_value >> 16);
	*(aucp_mem++) = (unsigned char) (imp_value >> 24);
	return aucp_mem;
}

HL_LOCAL_SCOPE unsigned char* m_safe_write_int32_be(unsigned char* aucp_mem, unsigned char* aucp_mem_end, int32_t imp_value) {
	if (aucp_mem + 4 > aucp_mem_end)
		return 0;
	*(aucp_mem++) = (unsigned char) (imp_value >> 24);
	*(aucp_mem++) = (unsigned char) (imp_value >> 16);
	*(aucp_mem++) = (unsigned char) (imp_value >>  8);
	*(aucp_mem++) = (unsigned char)  imp_value;
	return aucp_mem;
}

// Write functions as defined by [MS-RDPEI].pdf
#define SHIFTR_TRUNC8(val, shift) ((uint8_t)(((val) >> (shift)) & 0xFF))
#define SHIFTL_TRUNC8(val, shift) ((uint8_t)(((val) << (shift)) & 0xFF))

HL_LOCAL_SCOPE unsigned char *m_write_eight_byte_uint(unsigned char* aucp_oc, unsigned char* aucp_oe, uint64_t ulp_value) {

	unsigned char* aucl_oc = aucp_oc;
	unsigned char* aucl_oe = aucp_oe;

	unsigned char ucl_req_vals = (unsigned char)-1;

	if (ulp_value <= 0x1F)
		ucl_req_vals = 0;
	else if (ulp_value <= 0x1FFF)
		ucl_req_vals = 1;
	else if (ulp_value <= 0x1FFFFF)
		ucl_req_vals = 2;
	else if (ulp_value <= 0x1FFFFFFF)
		ucl_req_vals = 3;
	else if (ulp_value <= 0x1FFFFFFFFFull)
		ucl_req_vals = 4;
	else if (ulp_value <= 0x1FFFFFFFFFFFull)
		ucl_req_vals = 5;
	else if (ulp_value <= 0x1FFFFFFFFFFFFFull)
		ucl_req_vals = 6; 
	else if (ulp_value <= 0x1FFFFFFFFFFFFFFFull)
		ucl_req_vals = 7;

	if (aucl_oc + (ucl_req_vals + 1) > aucl_oe)
		return 0; // Error: Output Buffer overflow

	// c, val1
	switch (ucl_req_vals) {
	case 0:
		*(aucl_oc++) = (ucl_req_vals << 5) | (SHIFTR_TRUNC8(ulp_value, 0) & 0x1F);
		break;
	case 1:
		*(aucl_oc++) = (ucl_req_vals << 5) | (SHIFTR_TRUNC8(ulp_value, 8) & 0x1F);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 0);
		break;
	case 2:
		*(aucl_oc++) = (ucl_req_vals << 5) | (SHIFTR_TRUNC8(ulp_value, 16) & 0x1F);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 8);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 0);
		break;
	case 3:
		*(aucl_oc++) = (ucl_req_vals << 5) | (SHIFTR_TRUNC8(ulp_value, 24) & 0x1F);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 16);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 8);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 0);
		break;
	case 4:
		*(aucl_oc++) = (ucl_req_vals << 5) | (SHIFTR_TRUNC8(ulp_value, 32) & 0x1F);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 24);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 16);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 8);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 0);
		break;
	case 5:
		*(aucl_oc++) = (ucl_req_vals << 5) | (SHIFTR_TRUNC8(ulp_value, 40) & 0x1F);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 32);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 24);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 16);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 8);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 0);
		break;
	case 6:
		*(aucl_oc++) = (ucl_req_vals << 5) | (SHIFTR_TRUNC8(ulp_value, 48) & 0x1F);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 40);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 32);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 24);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 16);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 8);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 0);
		break;
	case 7:
		*(aucl_oc++) = (ucl_req_vals << 5) | (SHIFTR_TRUNC8(ulp_value, 56) & 0x1F);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 48);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 40);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 32);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 24);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 16);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 8);
		*(aucl_oc++) = SHIFTR_TRUNC8(ulp_value, 0);
		break;
	default:
		return 0; // Error: Invalid value
	}

	return aucl_oc;
}

HL_LOCAL_SCOPE unsigned char *m_write_four_byte_uint(unsigned char* aucp_oc, unsigned char* aucp_oe, uint32_t ump_value) {

	unsigned char* aucl_oc = aucp_oc;
	unsigned char* aucl_oe = aucp_oe;

	unsigned char ucl_req_vals = (unsigned char)-1;

	if (ump_value <= 0x3F)
		ucl_req_vals = 0;
	else if (ump_value <= 0x3FFF)
		ucl_req_vals = 1;
	else if (ump_value <= 0x3FFFFF)
		ucl_req_vals = 2;
	else if (ump_value <= 0x3FFFFFFF)
		ucl_req_vals = 3;

	if (aucl_oc + (ucl_req_vals + 1) > aucl_oe)
		return 0; // Error: Output Buffer overflow

	// c, val1
	switch (ucl_req_vals) {
	case 0:
		*(aucl_oc++) = SHIFTL_TRUNC8(ucl_req_vals, 6) | (SHIFTR_TRUNC8(ump_value, 0) & 0x3F);
		break;
	case 1:
		*(aucl_oc++) = SHIFTL_TRUNC8(ucl_req_vals, 6) | (SHIFTR_TRUNC8(ump_value, 8) & 0x3F);
		*(aucl_oc++) = SHIFTR_TRUNC8(ump_value, 0);
		break;
	case 2:
		*(aucl_oc++) = SHIFTL_TRUNC8(ucl_req_vals, 6) | (SHIFTR_TRUNC8(ump_value, 16) & 0x3F);
		*(aucl_oc++) = SHIFTR_TRUNC8(ump_value, 8);
		*(aucl_oc++) = SHIFTR_TRUNC8(ump_value, 0);
		break;
	case 3:
		*(aucl_oc++) = SHIFTL_TRUNC8(ucl_req_vals, 6) | (SHIFTR_TRUNC8(ump_value, 24) & 0x3F);
		*(aucl_oc++) = SHIFTR_TRUNC8(ump_value, 16);
		*(aucl_oc++) = SHIFTR_TRUNC8(ump_value, 8);
		*(aucl_oc++) = SHIFTR_TRUNC8(ump_value, 0);
		break;
	default: 
		return 0; // Error: Invalid value
	}

	return aucl_oc;
}

HL_LOCAL_SCOPE unsigned char *m_write_four_byte_sint(unsigned char* aucp_oc, unsigned char* aucp_oe, int32_t imp_value) {

	unsigned char* aucl_oc = aucp_oc;
	unsigned char* aucl_oe = aucp_oe;

	unsigned char ucl_req_vals = (unsigned char)-1;
	unsigned char ucl_sign = (unsigned char)-1;

	if (imp_value < 0x00) {
		ucl_sign = 1;
		imp_value = -imp_value;
	}
	else 
		ucl_sign = 0;

	if (imp_value <= 0x1F)
		ucl_req_vals = 0;
	else if (imp_value <= 0x1FFF)
		ucl_req_vals = 1;
	else if (imp_value <= 0x1FFFFF)
		ucl_req_vals = 2; 
	else if (imp_value <= 0x1FFFFFFF)
		ucl_req_vals = 3;

	if (aucl_oc + (ucl_req_vals + 1) > aucl_oe)
		return 0; // Error: Output Buffer overflow

	// c, val1
	switch (ucl_req_vals) {
	case 0:
		*(aucl_oc++) = SHIFTL_TRUNC8(ucl_req_vals, 6) | SHIFTL_TRUNC8(ucl_sign, 5) | (imp_value & 0x1F);
		break;
	case 1:
		*(aucl_oc++) = SHIFTL_TRUNC8(ucl_req_vals, 6) | SHIFTL_TRUNC8(ucl_sign, 5) | (SHIFTR_TRUNC8(imp_value, 8) & 0x1F);
		*(aucl_oc++) = SHIFTR_TRUNC8(imp_value, 0);
		break;
	case 2:
		*(aucl_oc++) = SHIFTL_TRUNC8(ucl_req_vals, 6) | SHIFTL_TRUNC8(ucl_sign, 5) | (SHIFTR_TRUNC8(imp_value, 16) & 0x1F);
		*(aucl_oc++) = SHIFTR_TRUNC8(imp_value, 8);
		*(aucl_oc++) = SHIFTR_TRUNC8(imp_value, 0);
		break;
	case 3:
		*(aucl_oc++) = SHIFTL_TRUNC8(ucl_req_vals, 6) | SHIFTL_TRUNC8(ucl_sign, 5) | (SHIFTR_TRUNC8(imp_value, 24) & 0x1F);
		*(aucl_oc++) = SHIFTR_TRUNC8(imp_value, 16);
		*(aucl_oc++) = SHIFTR_TRUNC8(imp_value, 8);
		*(aucl_oc++) = SHIFTR_TRUNC8(imp_value, 0);
		break;
	default: 
		return 0; // Error: Invalid value
	}

	return aucl_oc;
}



HL_LOCAL_SCOPE unsigned char *m_write_two_byte_uint(unsigned char* aucp_oc, unsigned char* aucp_oe, uint16_t usp_value) {

	unsigned char* aucl_oc = aucp_oc;
	unsigned char* aucl_oe = aucp_oe;

	unsigned char ucl_req_vals = (unsigned char)-1;

	if (usp_value <= 0x7F)
		ucl_req_vals = 0;
	else if (usp_value <= 0x7FFF)
		ucl_req_vals = 1;

	if (aucl_oc + (ucl_req_vals + 1) > aucl_oe)
		return 0; // Error: Output Buffer overflow

	// c, val1
	switch (ucl_req_vals) {
	case 0:
		*(aucl_oc++) = (ucl_req_vals << 7) | (usp_value & 0x7F);
		break;
	case 1:
		*(aucl_oc++) = (ucl_req_vals << 7) | ((usp_value & 0x7F00) >> 8);
		*(aucl_oc++) = (usp_value & 0xFF);
		break;
	default: 
		return 0; // Error: Invalid value
	}

	return aucl_oc;
}

HL_LOCAL_SCOPE unsigned char *m_write_two_byte_sint(unsigned char* aucp_oc, unsigned char* aucp_oe, int16_t isp_value) {

	unsigned char* aucl_oc = aucp_oc;
	unsigned char* aucl_oe = aucp_oe;

	unsigned char ucl_req_vals = (unsigned char)-1;
	unsigned char ucl_sign = (unsigned char)-1;

	if (isp_value < 0x00) {
		ucl_sign = 1;
		isp_value = -isp_value;
	}
	else 
		ucl_sign = 0;

	if (isp_value <= 0x3F)
		ucl_req_vals = 0;
	else if (isp_value <= 0x3FFF)
		ucl_req_vals = 1;

	if (aucl_oc + (ucl_req_vals + 1) > aucl_oe)
		return 0; // Error: Output Buffer overflow

	// c, val1
	switch (ucl_req_vals) {
	case 0:
		*(aucl_oc++) = (ucl_req_vals << 7) | (ucl_sign << 6) | (isp_value & 0x3F);
		break;
	case 1:
		*(aucl_oc++) = (ucl_req_vals << 7) | (ucl_sign << 6) | ((isp_value & 0x3F00) >> 8);
		*(aucl_oc++) = (isp_value & 0xFF);
		break;
	default: 
		return 0; // Error: Invalid value
	}

	return aucl_oc;
}

#endif