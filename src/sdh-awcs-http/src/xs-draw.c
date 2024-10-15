/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| --------                                                            |*/
/*|   xs-draw                                                           |*/
/*|   Canvas Drawing Functions                                          |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|   Tobias Hofmann, March 2012                                        |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

#ifndef HL_UNIX
    #include <windows.h>
	#pragma warning(disable:4996)       /* windows warning for vnsprintf */
#endif //HL_UNIX
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

/*+---------------------------------------------------------------------+*/
/*| local includes:                                                     |*/
/*+---------------------------------------------------------------------+*/
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H

#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

#include <hob-xs-html5.h>
#include <hob-xs-draw.h>

static const struct dsd_string_const dsg_json_object[] = {
    { "{\"draw\":\"", 9 },
    { "\"}"         , 2 }
};

/*+---------------------------------------------------------------------+*/
/*| public canvas 2D drawing functions:                                 |*/
/*+---------------------------------------------------------------------+*/

/**
 * public function m_c2d_save
 *  canvas 2D command:
 *  void save()
 *
 * @param[in]   dsd_canvas_ctx *adsp_ctx
 * @return      BOOL
*/
extern BOOL m_c2d_save( struct dsd_html5_answer *adsp_answer )
{
    const char *achl_temp = "ctx.save();";

    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < strlen( achl_temp ) ){ return FALSE; }

    strcpy( adsp_answer->chrc_answer + adsp_answer->inc_len, achl_temp );
    adsp_answer->inc_len += strlen(achl_temp);
    
    return TRUE;
} /* end of m_c2d_save */


/**
 * public function m_c2d_restore
 *  canvas 2D command:
 *  void restore()
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @return      BOOL
*/
extern BOOL m_c2d_restore( struct dsd_html5_answer *adsp_answer )
{
    const char   *achl_temp = "ctx.restore();";

    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < strlen( achl_temp ) ){ return FALSE; }

    strcpy( adsp_answer->chrc_answer + adsp_answer->inc_len, achl_temp );
    adsp_answer->inc_len += strlen(achl_temp);
    
    return TRUE;
} /* end of m_c2d_restore */


/**
 * public function m_c2d_scale
 *  canvas 2D command:
 *  void scale(in double x, in double y)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   float           flp_x
 * @param[in]   float           flp_y
 * @return      BOOL
*/
extern BOOL m_c2d_scale( struct dsd_html5_answer *adsp_answer,
                         float flp_x, float flp_y         )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.scale(%f,%f);", flp_x, flp_y );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_scale */


/**
 * public function m_c2d_rotate
 *  canvas 2D command:
 *  void rotate(in double angle)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   float           flp_x
 * @param[in]   float           flp_y
 * @return      BOOL
*/
extern BOOL m_c2d_rotate( struct dsd_html5_answer *adsp_answer,
                          float flp_angle                  )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.rotate(%f);", flp_angle );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_rotate */


/**
 * public function m_c2d_translate
 *  canvas 2D command:
 *  void translate(in double x, in double y)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   float           flp_x
 * @param[in]   float           flp_y
 * @return      BOOL
*/
extern BOOL m_c2d_translate( struct dsd_html5_answer *adsp_answer,
                             float flp_x, float flp_y         )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.translate(%f,%f);", flp_x, flp_y );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_translate */


/**
 * public function m_c2d_transfrom
 *  canvas 2D command:
 *  void transform(in double a, in double b, in double c, in double d, in double e, in double f)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   float           flp_a
 * @param[in]   float           flp_b
 * @param[in]   float           flp_c
 * @param[in]   float           flp_d
 * @param[in]   float           flp_e
 * @param[in]   float           flp_f
 * @return      BOOL
*/
extern BOOL m_c2d_transfrom( struct dsd_html5_answer *adsp_answer,
                             float flp_a, float flp_b, float flp_c,
                             float flp_d, float flp_e, float flp_f )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.transform(%f,%f,%f,%f,%f,%f);",
                          flp_a, flp_b, flp_c, flp_d, flp_e, flp_f );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_transfrom */


/**
 * public function m_c2d_set_transfrom
 *  canvas 2D command:
 *  void setTransform(in double a, in double b, in double c, in double d, in double e, in double f)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   float           flp_a
 * @param[in]   float           flp_b
 * @param[in]   float           flp_c
 * @param[in]   float           flp_d
 * @param[in]   float           flp_e
 * @param[in]   float           flp_f
 * @return      BOOL
*/
extern BOOL m_c2d_set_transfrom( struct dsd_html5_answer *adsp_answer,
                                 float flp_a, float flp_b, float flp_c,
                                 float flp_d, float flp_e, float flp_f )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.setTransform(%f,%f,%f,%f,%f,%f);",
                          flp_a, flp_b, flp_c, flp_d, flp_e, flp_f );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_set_transfrom */


/**
 * public function m_c2d_global_alpha
 *  set canvas 2D attribute:
 *  attribute double globalAlpha
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   float           flp_alpha
 * @return      BOOL
*/
extern BOOL m_c2d_global_alpha( struct dsd_html5_answer *adsp_answer,
                                float flp_alpha                  )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.globalAlpha=%f;", flp_alpha );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_global_alpha */


/**
 * public function m_c2d_global_alpha
 *  set canvas 2D attribute:
 *  attribute DOMString globalCompositeOperation
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_comp
 * @return      BOOL
*/
extern BOOL m_c2d_global_composite_operation( struct dsd_html5_answer *adsp_answer,
                                              const char *achp_comp            )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.globalCompositeOperation=%s;", achp_comp );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_global_alpha */


/**
 * public function m_c2d_stroke_style
 *  set canvas 2D attribute:
 *  attribute any strokeStyle
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_style
 * @return      BOOL
*/
extern BOOL m_c2d_stroke_style( struct dsd_html5_answer *adsp_answer,
                                const char *achp_style           )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.strokeStyle=%s;", achp_style );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_stroke_style */


/**
 * public function m_c2d_fill_style
 *  set canvas 2D attribute:
 *  attribute any fillStyle
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_style
 * @return      BOOL
*/
extern BOOL m_c2d_fill_style( struct dsd_html5_answer *adsp_answer,
                              const char *achp_style           )
{
    size_t uinl_len;
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.fillStyle=%s;", achp_style );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_fill_style */


/**
 * public function m_c2d_create_linear_gradient
 *  call canvas 2D function:
 *  CanvasGradient createLinearGradient(in double x0, in double y0, in double x1, in double y1)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_gradient
 * @param[in]   float           flp_x0
 * @param[in]   float           flp_y0
 * @param[in]   float           flp_x1
 * @param[in]   float           flp_y1
 * @return      BOOL
*/
extern BOOL m_c2d_create_linear_gradient( struct dsd_html5_answer *adsp_answer,
                                          const char *achp_gradient,
                                          float flp_x0, float flp_y0,
                                          float flp_x1, float flp_y1 )
{
    size_t uinl_len;
    
    if ( achp_gradient != NULL ) {
        uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                              HTML5_ANSWER_LEN - adsp_answer->inc_len,
                              "%s=ctx.createLinearGradient(%f,%f,%f,%f);",
                              achp_gradient, flp_x0, flp_y0, flp_x1, flp_y1 );
    } else {
        uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                              HTML5_ANSWER_LEN - adsp_answer->inc_len,
                              "ctx.createLinearGradient(%f,%f,%f,%f);",
                              flp_x0, flp_y0, flp_x1, flp_y1 );
    }
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_create_linear_gradient */


/**
 * public function m_c2d_create_radial_gradient
 *  call canvas 2D function:
 *  CanvasGradient createRadialGradient(in double x0, in double y0, in double r0, in double x1, in double y1, in double r1)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_gradient
 * @param[in]   float           flp_x0
 * @param[in]   float           flp_y0
 * @param[in]   float           flp_r0
 * @param[in]   float           flp_x1
 * @param[in]   float           flp_y1
 * @param[in]   float           flp_r1
 * @return      BOOL
*/
extern BOOL m_c2d_create_radial_gradient( struct dsd_html5_answer *adsp_answer,
                                          const char *achp_gradient,
                                          float flp_x0, float flp_y0, float flp_r0,
                                          float flp_x1, float flp_y1, float flp_r1 )
{
    size_t uinl_len;
    
    if ( achp_gradient != NULL ) {
        uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                              HTML5_ANSWER_LEN - adsp_answer->inc_len,
                              "%s=ctx.createRadialGradient(%f,%f,%f,%f,%f,%f);",
                              achp_gradient,
                              flp_x0, flp_y0, flp_r0, flp_x1, flp_y1, flp_r1 );
    } else {
        uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                              HTML5_ANSWER_LEN - adsp_answer->inc_len,
                              "ctx.createRadialGradient(%f,%f,%f,%f,%f,%f);",
                              flp_x0, flp_y0, flp_r0, flp_x1, flp_y1, flp_r1 );
    }
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_create_radial_gradient */


/**
 * public function m_c2d_add_color_stop
 *  call canvas 2D function:
 *  void addColorStop(in double offset, in DOMString color )
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_gradient
 * @param[in]   float           flp_offset
 * @param[in]   const char      *achp_color
 * @return      BOOL
*/
extern BOOL m_c2d_add_color_stop( struct dsd_html5_answer *adsp_answer,
                                  const char *achp_gradient,
                                  float flp_offset, const char *achp_color )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "%s.addColorStop(%f,%s);",
                          achp_gradient, flp_offset, achp_color );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_add_color_stop */


/**
 * public function m_c2d_create_pattern
 *  call canvas 2D function:
 *  CanvasPattern createPattern(in HTMLImageElement image, in DOMString repetition)
 *  CanvasPattern createPattern(in HTMLCanvasElement image, in DOMString repetition)
 *  CanvasPattern createPattern(in HTMLVideoElement image, in DOMString repetition)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_pattern
 * @param[in]   const char      *achp_image
 * @param[in]   size_t          uinp_size
 * @param[in]   const char      *achp_repetition
 * @return      BOOL
*/
extern BOOL m_c2d_create_pattern( struct dsd_html5_answer *adsp_answer,
                                  const char *achp_pattern,
                                  const char *achp_image, size_t uinp_size,
                                  const char *achp_repetition )
{
    size_t uinl_len;
    
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "var img=new Image();img.src='" );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;
  
    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < uinp_size ){ return FALSE; }
    memcpy( adsp_answer->chrc_answer + adsp_answer->inc_len, achp_image, uinp_size );
    adsp_answer->inc_len += uinp_size;

    if ( achp_pattern != NULL )
    {
        uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                              HTML5_ANSWER_LEN - adsp_answer->inc_len,
                              "';%s=ctx.createPattern(img,'%s');",
                              achp_pattern, achp_repetition );
    }
    else
    {
        uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                              HTML5_ANSWER_LEN - adsp_answer->inc_len,
                              "';ctx.createPattern(img,'%s');",
                              achp_repetition );
    }
    if ( uinl_len < 1 ) { return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
    
} /* end of m_c2d_create_pattern */


/**
 * public function m_c2d_line_width
 *  set canvas 2D attribute:
 *  attribute double lineWidth
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigend int    uinp_width
 * @return      BOOL
*/
extern BOOL m_c2d_line_width( struct dsd_html5_answer *adsp_answer,
                              unsigned int uinp_width          )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.lineWidth=%u;", uinp_width );
    if ( uinl_len < 1 ) { return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_line_width */


/**
 * public function m_c2d_line_cap
 *  set canvas 2D attribute:
 *  attribute DOMString lineCap
 * "butt", "round", "square"
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_cap
 * @return      BOOL
*/
extern BOOL m_c2d_line_cap( struct dsd_html5_answer *adsp_answer,
                            const char *achp_cap             )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.lineCap=%s;", achp_cap );
    if ( uinl_len < 1 ) { return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_line_cap */


/**
 * public function m_c2d_line_join
 *  set canvas 2D attribute:
 *  attribute DOMString lineJoin
 * "round", "bevel", "miter"
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_cap
 * @return      BOOL
*/
extern BOOL m_c2d_line_join( struct dsd_html5_answer *adsp_answer,
                             const char *achp_join            )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.lineJoin=%s;", achp_join );
    if ( uinl_len < 1 ) { return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_line_join */


/**
 * public function m_c2d_miter_limit
 *  set canvas 2D attribute:
 *  attribute double miterLimit
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_limit
 * @return      BOOL
*/
extern BOOL m_c2d_miter_limit( struct dsd_html5_answer *adsp_answer,
                               unsigned int uinp_limit          )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.miterLimit=%u;", uinp_limit );
    if ( uinl_len < 1 ) { return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_miter_limit */


/**
 * public function m_c2d_shadow_offset_x
 *  set canvas 2D attribute:
 *  attribute double shadowOffsetX
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_shadow
 * @return      BOOL
*/
extern BOOL m_c2d_shadow_offset_x( struct dsd_html5_answer *adsp_answer,
                                   unsigned int uinp_shadow         )
{
    size_t uinl_len;
    
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.shadowOffsetX=%u;", uinp_shadow );
    if ( uinl_len < 1 ) { return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_shadow_offset_x */


/**
 * public function m_c2d_shadow_offset_y
 *  set canvas 2D attribute:
 *  attribute double shadowOffsetY
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_shadow
 * @return      BOOL
*/
extern BOOL m_c2d_shadow_offset_y( struct dsd_html5_answer *adsp_answer,
                                   unsigned int uinp_shadow         )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.shadowOffsetY=%u;", uinp_shadow );
    if ( uinl_len < 1 ) { return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_shadow_offset_y */


/**
 * public function m_c2d_shadow_blur
 *  set canvas 2D attribute:
 *  attribute double shadowBlur
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_shadow
 * @return      BOOL
*/
extern BOOL m_c2d_shadow_blur( struct dsd_html5_answer *adsp_answer,
                               unsigned int uinp_shadow         )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.shadowBlur=%u;", uinp_shadow );
    if ( uinl_len < 1 ) { return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_shadow_blur */


/**
 * public function m_c2d_shadow_color
 *  set canvas 2D attribute:
 *  attribute DOMString shadowColor
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_color
 * @return      BOOL
*/
extern BOOL m_c2d_shadow_color( struct dsd_html5_answer *adsp_answer,
                                const char *achp_color           )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.shadowColor=%s;", achp_color );
    if ( uinl_len < 1 ) { return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_shadow_color */


/**
 * public function m_c2d_clear_rect
 *  canvas 2D command:
 *  void clearRect(in double x, in double y, in double w, in double h)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @param[in]   unsigned int    uinp_width
 * @param[in]   unsigned int    uinp_height
 * @return      BOOL
*/
extern BOOL m_c2d_clear_rect( struct dsd_html5_answer *adsp_answer,
                              unsigned int uinp_x, unsigned int uinp_y,
                              unsigned int uinp_width, unsigned int uinp_height )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.clearRect(%u,%u,%u,%u);",
                          uinp_x, uinp_y, uinp_width, uinp_height );
    
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_clear_rect */


/**
 * public function m_c2d_fill_rect
 *  canvas 2D command:
 *  void fillRect(in double x, in double y, in double w, in double h)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @param[in]   unsigned int    uinp_width
 * @param[in]   unsigned int    uinp_height
 * @return      BOOL
*/
extern BOOL m_c2d_fill_rect( struct dsd_html5_answer *adsp_answer,
                             unsigned int uinp_x, unsigned int uinp_y,
                             unsigned int uinp_width, unsigned int uinp_height )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.fillRect(%u,%u,%u,%u);",
                          uinp_x, uinp_y, uinp_width, uinp_height );

    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_fill_rect */


/**
 * public function m_c2d_stroke_rect
 *  canvas 2D command:
 *  void strokeRect(in double x, in double y, in double w, in double h)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @param[in]   unsigned int    uinp_width
 * @param[in]   unsigned int    uinp_height
 * @return      BOOL
*/
extern BOOL m_c2d_stroke_rect( struct dsd_html5_answer  *adsp_answer,
                               unsigned int uinp_x, unsigned int uinp_y,
                               unsigned int uinp_width, unsigned int uinp_height )
{
    size_t uinl_len;
    

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.strokeRect(%u,%u,%u,%u);",
                          uinp_x, uinp_y, uinp_width, uinp_height );
    if ( uinl_len < 1 ) {
        return FALSE;
    }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_stroke_rect */


/**
 * public function m_c2d_begin_path
 *  canvas 2D command:
 *  void beginPath()
 *
 * @param[in]   dsd_canvas_ctx *adsp_ctx
 * @return      BOOL
*/
extern BOOL m_c2d_begin_path( struct dsd_html5_answer *adsp_answer )
{
    const char   *achl_temp = "ctx.beginPath();";

    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < strlen( achl_temp ) ){ return FALSE; }

    strcpy( adsp_answer->chrc_answer + adsp_answer->inc_len, achl_temp );
    adsp_answer->inc_len += strlen(achl_temp);
    
    return TRUE;
} /* end of m_c2d_begin_path */


/**
 * public function m_c2d_close_path
 *  canvas 2D command:
 *  void closePath()
 *
 * @param[in]   dsd_canvas_ctx *adsp_ctx
 * @return      BOOL
*/
extern BOOL m_c2d_close_path( struct dsd_html5_answer *adsp_answer  )
{
    char   *achl_temp = "ctx.closePath();";

    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < strlen( achl_temp ) ){ return FALSE; }

    strcpy( adsp_answer->chrc_answer + adsp_answer->inc_len, achl_temp );
    adsp_answer->inc_len += strlen(achl_temp);
    
    return TRUE;
} /* end of m_c2d_close_path */


/**
 * public function m_c2d_move_to
 *  canvas 2D command:
 *  void moveTo(in double x, in double y)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @return      BOOL
*/
extern BOOL m_c2d_move_to( struct dsd_html5_answer  *adsp_answer,
                           unsigned int uinp_x, unsigned int uinp_y )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.moveTo(%u,%u);", uinp_x, uinp_y );
    
    if ( uinl_len < 1 ) {
        return FALSE;
    }
    adsp_answer->inc_len += uinl_len;

    return TRUE;

} /* end of m_c2d_move_to */


/**
 * public function m_c2d_line_to
 *  canvas 2D command:
 *  void lineTo(in double x, in double y)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @return      BOOL
*/
extern BOOL m_c2d_line_to( struct dsd_html5_answer *adsp_answer,
                           unsigned int uinp_x, unsigned int uinp_y )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.lineTo(%u,%u);", uinp_x, uinp_y );

    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_line_to */


/**
 * public function m_c2d_quadratic_curve_to
 *  canvas 2D command:
 *  void quadraticCurveTo(in double cpx, in double cpy, in double x, in double y)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    flp_cpx
 * @param[in]   unsigned int    flp_cpy
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @return      BOOL
*/
extern BOOL m_c2d_quadratic_curve_to( struct dsd_html5_answer *adsp_answer,
                                      unsigned int uinp_cpx, unsigned int uinp_cpy,
                                      unsigned int uinp_x, unsigned int uinp_y    )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.quadraticCurveTo(%u,%u,%u,%u);",
                          uinp_cpx, uinp_cpy, uinp_x, uinp_y );
    
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;

} /* end of m_c2d_quadratic_curve_to */


/**
 * public function m_c2d_bezier_curve_to
 *  canvas 2D command:
 *  void bezierCurveTo(in double cp1x, in double cp1y, in double cp2x, in double cp2y, in double x, in double y)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    flp_cp1x
 * @param[in]   unsigned int    flp_cp1y
 * @param[in]   unsigned int    flp_cp2x
 * @param[in]   unsigned int    flp_cp2y
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @return      BOOL
*/
extern BOOL m_c2d_bezier_curve_to( struct dsd_html5_answer *adsp_answer,
                                   unsigned int uinp_cp1x, unsigned int uinp_cp1y,
                                   unsigned int uinp_cp2x, unsigned int uinp_cp2y,
                                   unsigned int uinp_x, unsigned int uinp_y )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.bezierCurveTo(%u,%u,%u,%u,%u,%u);",
                          uinp_cp1x, uinp_cp1y,
                          uinp_cp2x, uinp_cp2y, uinp_x, uinp_y );

    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_bezier_curve_to */


/**
 * public function m_c2d_arc_to
 *  canvas 2D command:
 *  void arcTo(in double x1, in double y1, in double x2, in double y2, in double radius)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_x1
 * @param[in]   unsigned int    uinp_y1
 * @param[in]   unsigned int    uinp_x2
 * @param[in]   unsigned int    uinp_y2
 * @param[in]   float           flp_radius
 * @return      BOOL
*/
extern BOOL m_c2d_arc_to( struct dsd_html5_answer *adsp_answer,
                          unsigned int uinp_x1, unsigned int uinp_y1,
                          unsigned int uinp_x2, unsigned int uinp_y2,
                          float flp_radius                  )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.arcTo(%u,%u,%u,%u,%f);",
                          uinp_x1, uinp_y1, uinp_x2, uinp_y2, flp_radius );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_arc_to */


/**
 * public function m_c2d_rect
 *  canvas 2D command:
 *  void rect(in double x, in double y, in double w, in double h)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @param[in]   unsigned int    uinp_width
 * @param[in]   unsigned int    uinp_height
 * @return      BOOL
*/
extern BOOL m_c2d_rect( struct dsd_html5_answer *adsp_answer,
                        unsigned int uinp_x, unsigned int uinp_y,
                        unsigned int uinp_width, unsigned int uinp_height )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.rect(%u,%u,%u,%u);",
                          uinp_x, uinp_y, uinp_width, uinp_height );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_rect */


/**
 * public function m_c2d_arc
 *  canvas 2D command:
 *  void arc(in double x, in double y, in double radius, in double startAngle, in double endAngle, in optional boolean anticlockwise)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @param[in]   float           flp_radius
 * @param[in]   float           flp_start_angle
 * @param[in]   float           flp_end_angle
 * @param[in]   BOOL            bop_clockwise
 * @return      BOOL
*/
extern BOOL m_c2d_arc( struct dsd_html5_answer  *adsp_answer,
                       unsigned int uinp_x, unsigned int uinp_y,
                       float flp_radius,
                       float flp_start_angle, float flp_end_angle,
                       BOOL bop_clockwise )
{
    size_t uinl_len;
    
    if ( bop_clockwise == TRUE ) {
        uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                              HTML5_ANSWER_LEN - adsp_answer->inc_len,
                              "ctx.arc(%u,%u,%f,%f,%f);",
                              uinp_x, uinp_y, flp_radius,
                              flp_start_angle, flp_end_angle );
    } else {
        uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                              HTML5_ANSWER_LEN - adsp_answer->inc_len,
                              "ctx.arc(%u,%u,%f,%f,%f,true);",
                              uinp_x, uinp_y, flp_radius,
                              flp_start_angle, flp_end_angle );
    }

    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_rect */


/**
 * public function m_c2d_fill
 *  canvas 2D command:
 *  void fill()
 *
 * @param[in]   dsd_canvas_ctx *adsp_ctx
 * @return      BOOL
*/
extern BOOL m_c2d_fill( struct dsd_html5_answer  *adsp_answer )
{
    char   *achl_temp = "ctx.fill();";

    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < strlen( achl_temp ) ){ return FALSE; }

    strcpy( adsp_answer->chrc_answer + adsp_answer->inc_len, achl_temp );
    adsp_answer->inc_len += strlen(achl_temp);
    
    return TRUE;
} /* end of m_c2d_fill */


/**
 * public function m_c2d_stroke
 *  canvas 2D command:
 *  void stroke()
 *
 * @param[in]   dsd_canvas_ctx *adsp_ctx
 * @return      BOOL
*/
extern BOOL m_c2d_stroke( struct dsd_html5_answer  *adsp_answer )
{
    const char *achl_temp = "ctx.stroke();";

    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < strlen( achl_temp ) ){ return FALSE; }

    strcpy( adsp_answer->chrc_answer + adsp_answer->inc_len, achl_temp );
    adsp_answer->inc_len += strlen(achl_temp);
    
    return TRUE;
} /* end of m_c2d_stroke */


/**
 * public function m_c2d_draw_system_focus_ring
 *  canvas 2D command:
 *  void drawSystemFocusRing(in Element element)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_elem
 * @return      BOOL
*/
extern BOOL m_c2d_draw_system_focus_ring( struct dsd_html5_answer  *adsp_answer,
                                          const char *achp_element )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.drawSystemFocusRing(%s);", achp_element );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_draw_system_focus_ring */


/**
 * public function m_c2d_draw_custom_focus_ring
 *  canvas 2D command:
 *  boolean drawCustomFocusRing(in Element element)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_elem
 * @return      BOOL
*/
extern BOOL m_c2d_draw_custom_focus_ring( struct dsd_html5_answer  *adsp_answer,
                                          const char *achp_element )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.drawCustomFocusRing(%s);", achp_element );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_draw_custom_focus_ring */


/**
 * public function m_c2d_scroll_path_into_view
 *  canvas 2D command:
 *  void scrollPathIntoView()
 *
 * @param[in]   dsd_canvas_ctx *adsp_ctx
 * @return      BOOL
*/
extern BOOL m_c2d_scroll_path_into_view( struct dsd_html5_answer  *adsp_answer )
{
    char   *achl_temp = "ctx.scrollPathIntoView();";

    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < strlen( achl_temp ) ){ return FALSE; }

    strcpy( adsp_answer->chrc_answer + adsp_answer->inc_len, achl_temp );
    adsp_answer->inc_len += strlen(achl_temp);
    
    return TRUE;
} /* end of m_c2d_scroll_path_into_view */


/**
 * public function m_c2d_clip
 *  canvas 2D command:
 *  void clip()
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @return      BOOL
*/
extern BOOL m_c2d_clip( struct dsd_html5_answer  *adsp_answer )
{
    char   *achl_temp = "ctx.clip();";
    
    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < strlen( achl_temp ) ){ return FALSE; }

    strcpy( adsp_answer->chrc_answer + adsp_answer->inc_len, achl_temp );
    adsp_answer->inc_len += strlen(achl_temp);
    
    return TRUE;
} /* end of m_c2d_clip */


/**
 * public function m_c2d_is_point_in_path
 *  canvas 2D command:
 *  boolean isPointInPath(in double x, in double y)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @return      BOOL
*/
extern BOOL m_c2d_is_point_in_path( struct dsd_html5_answer  *adsp_answer,
                                    unsigned int uinp_x, unsigned int uinp_y )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.isPointInPath(%u,%u);", uinp_x, uinp_y );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_is_point_in_path */


/**
 * public function m_c2d_font
 *  set canvas 2D attribute:
 *  attribute DOMString font
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_font
 * @return      BOOL
*/
extern BOOL m_c2d_font( struct dsd_html5_answer  *adsp_answer,
                        const char *achp_font            )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.font='%s';", achp_font );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_font */


/**
 * public function m_c2d_text_align
 *  set canvas 2D attribute:
 *  attribute DOMString textAlign
 *  "start", "end", "left", "right", "center"
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_align
 * @return      BOOL
*/
extern BOOL m_c2d_text_align( struct dsd_html5_answer  *adsp_answer,
                              const char *achp_align            )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.textAlign='%s';", achp_align );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_text_align */


/**
 * public function m_c2d_text_base_line
 *  set canvas 2D attribute:
 *  attribute DOMString textBaseline
 *  "top", "hanging", "middle", "alphabetic", "ideographic", "bottom"
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_baseline
 * @return      BOOL
*/
extern BOOL m_c2d_text_base_line( struct dsd_html5_answer  *adsp_answer,
                                  const char *achp_baseline         )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.textBaseline=%s;", achp_baseline );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_text_base_line */


/**
 * public function m_c2d_fill_text
 *  canvas 2D function:
 *  void fillText(in DOMString text, in double x, in double y, in optional double maxWidth)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_text
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @return      BOOL
*/
extern BOOL m_c2d_fill_text( struct dsd_html5_answer  *adsp_answer,
                             const char *achp_text,
                             unsigned int uinp_x, unsigned int uinp_y )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.fillText('%s',%u,%u);", achp_text, uinp_x, uinp_y );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_fill_text */


/**
 * public function m_c2d_stroke_text
 *  canvas 2D function:
 *  void strokeText(in DOMString text, in double x, in double y, in optional double maxWidth)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_text
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @return      BOOL
*/
extern BOOL m_c2d_stroke_text( struct dsd_html5_answer  *adsp_answer,
                               const char *achp_text,
                               unsigned int uinp_x, unsigned int uinp_y )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.strokeText('%s',%u,%u);", achp_text, uinp_x, uinp_y );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_stroke_text */


/**
 * public function m_c2d_measure_text
 *  canvas 2D function:
 *  TextMetrics measureText(in DOMString text)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_text
 * @return      BOOL
*/
extern BOOL m_c2d_measure_text( struct dsd_html5_answer  *adsp_answer,
                                const char *achp_text )
{
    size_t uinl_len;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.measureText(%s);", achp_text );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_measure_text */


/**
 * public function m_c2d_draw_image1
 *  canvas 2D function:
 *  void drawImage(in HTMLImageElement image, in double dx, in double dy)
 *  void drawImage(in HTMLCanvasElement image, in double dx, in double dy)
 *  void drawImage(in HTMLVideoElement image, in double dx, in double dy)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_image
 * @param[in]   size_t          uinp_size
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @return      BOOL
*/
extern BOOL m_c2d_draw_image1( struct dsd_html5_answer *adsp_answer,
                               const char *achp_image, size_t uinp_size,
                               unsigned int uinp_x, unsigned int uinp_y )
{
    size_t uinl_len;
        
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "var img=new Image();img.src='" );

    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < uinp_size ){ return FALSE; }
    memcpy( adsp_answer->chrc_answer + adsp_answer->inc_len, achp_image, uinp_size );
    adsp_answer->inc_len += uinp_size;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "';ctx.drawImage(img,%u,%u);", uinp_x, uinp_y );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;
    
    return TRUE;
} /* end of m_c2d_draw_image1 */


/**
 * public function m_c2d_draw_image2
 *  canvas 2D function:
 *  void drawImage(in HTMLImageElement image, in double dx, in double dy, in double dw, in double dh)
 *  void drawImage(in HTMLCanvasElement image, in double dx, in double dy, in double dw, in double dh)
 *  void drawImage(in HTMLVideoElement image, in double dx, in double dy, in double dw, in double dh)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_image
 * @param[in]   unsigned int    uinp_dx
 * @param[in]   unsigned int    uinp_dy
 * @param[in]   unsigned int    uinp_dw
 * @param[in]   unsigned int    uinp_dh
 * @return      BOOL
*/
extern BOOL m_c2d_draw_image2( struct dsd_html5_answer *adsp_answer,
                               const char *achp_image,
                               unsigned int uinp_dx, unsigned int uinp_dy,
                               unsigned int uinp_dw, unsigned int uinp_dh )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.drawImage(%s,%u,%u,%u,%u);",
                          achp_image, uinp_dx, uinp_dy, uinp_dw, uinp_dh );

    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;
    
    return TRUE;
} /* end of m_c2d_draw_image2 */


/**
 * public function m_c2d_draw_image3
 *  canvas 2D function:
 *  void drawImage(in HTMLImageElement image, in double sx, in double sy, in double sw, in double sh, in double dx, in double dy, in double dw, in double dh)
 *  void drawImage(in HTMLCanvasElement image, in double sx, in double sy, in double sw, in double sh, in double dx, in double dy, in double dw, in double dh)
 *  void drawImage(in HTMLVideoElement image, in double sx, in double sy, in double sw, in double sh, in double dx, in double dy, in double dw, in double dh)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_image
 * @param[in]   unsigned int    uinp_sx
 * @param[in]   unsigned int    uinp_sy
 * @param[in]   unsigned int    uinp_sw
 * @param[in]   unsigned int    uinp_sh
 * @param[in]   unsigned int    uinp_dx
 * @param[in]   unsigned int    uinp_dy
 * @param[in]   unsigned int    uinp_dw
 * @param[in]   unsigned int    uinp_dh
 * @return      BOOL
*/
extern BOOL m_c2d_draw_image3( struct dsd_html5_answer *adsp_answer,
                               const char *achp_image,
                               unsigned int uinp_sx, unsigned int uinp_sy,
                               unsigned int uinp_sw, unsigned int uinp_sh,
                               unsigned int uinp_dx, unsigned int uinp_dy,
                               unsigned int uinp_dw, unsigned int uinp_dh )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.drawImage(%s,%u,%u,%u,%u,%u,%u,%u,%u);",
                          achp_image,
                          uinp_sx, uinp_sy, uinp_sw, uinp_sh,
                          uinp_dx, uinp_dy, uinp_dw, uinp_dh );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;
    
    return TRUE;
} /* end of m_c2d_draw_image3 */


/**
 * public function m_c2d_sprintf
 *  sprintf like generic function
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_format
 * @return      BOOL
*/
extern BOOL m_c2d_sprintf( struct dsd_html5_answer *adsp_answer,
                           const char              *achp_format, ... )
{
    int     inl_written;                        /* written bytes         */
    va_list dsl_args;                           /* argument list         */

    va_start( dsl_args, achp_format );
    inl_written = vsnprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                             HTML5_ANSWER_LEN - adsp_answer->inc_len,
                             achp_format,
                             dsl_args );
    va_end( dsl_args );

    if (    inl_written <= 0
         || inl_written > (HTML5_ANSWER_LEN - adsp_answer->inc_len) ) {
        return FALSE;
    }
    
    adsp_answer->inc_len += inl_written;
    return TRUE;
} /* end of m_c2d_sprintf */


/**
 * public function m_c2d_cache_func
 *  cache a given function witht the name achp_name
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_name      function name
 * @param[in]   const char      *achp_function  function content
 * @return      BOOL
*/
extern BOOL m_c2d_cache_func( struct dsd_html5_answer *adsp_answer,
                              const char *achp_name,
                              const char *achp_function        )
{
    size_t uinl_len;
     
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "cvs.cache('%s','%s');",
                          achp_name, achp_function );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;
    
    return TRUE;
} /* end of m_c2d_cache_func */


/**
 * public function m_c2d_cache_image
 *  cache a given image with the name achp_name
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_name      image name
 * @param[in]   const char      *achp_image     image content
 * @param[in]   size_t          uinp_size       length of image
 * @return      BOOL
*/
extern BOOL m_c2d_cache_image( struct dsd_html5_answer *adsp_answer,
                               const char *achp_name,
                               const char *achp_image, size_t uinp_size )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "cvs.cache('%s','new Image()');cvs.%s.src='",
                          achp_name, achp_name );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;


    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < uinp_size ){ return FALSE; }
    memcpy( adsp_answer->chrc_answer + adsp_answer->inc_len, achp_image, uinp_size );
    adsp_answer->inc_len += uinp_size;

    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len, "';" );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_cache_image */

/**
 * public function m_c2d_draw_cached_image1
 *  draw a cached image with the name achp_name
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   const char      *achp_name      image name
 * @param[in]   unsigned int    uinp_x
 * @param[in]   unsigned int    uinp_y
 * @return      BOOL
*/
extern BOOL m_c2d_draw_cached_image1( struct dsd_html5_answer *adsp_answer,
                                      const char *achp_name,
                                      unsigned int uinp_x, unsigned int uinp_y )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.drawImage(cvs.%s,%u,%u);",
                          achp_name, uinp_x, uinp_y );

    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_draw_cached_image1 */


/**
 * public function m_c2d_copy
 *  canvas 2D command:
 *  void putImageData(getImageData(in double sx, in double sy, in double sw, in double sh), in double dx, in double dy)
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_from_x
 * @param[in]   unsigned int    uinp_from_y
 * @param[in]   unsigned int    uinp_width
 * @param[in]   unsigned int    uinp_height
 * @param[in]   unsigned int    uinp_to_x
 * @param[in]   unsigned int    uinp_to_y
 * @return      BOOL
*/
extern BOOL m_c2d_copy( struct dsd_html5_answer *adsp_answer,
                        unsigned int uinp_from_x, unsigned int uinp_from_y,
                        unsigned int uinp_width, unsigned int uinp_height,
                        unsigned int uinp_to_x, unsigned int uinp_to_y      )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "ctx.putImageData(ctx.getImageData(%u,%u,%u,%u),%u,%u);",
                          uinp_from_x, uinp_from_y, uinp_width, uinp_height,
                          uinp_to_x, uinp_to_y );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_copy */


/**
 * public function m_c2d_set_window_size
 *  set canvas window size
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @param[in]   unsigned int    uinp_width
 * @param[in]   unsigned int    uinp_height
 * @return      BOOL
*/
extern BOOL m_c2d_set_window_size( struct dsd_html5_answer *adsp_answer,
                                   unsigned int uinp_width,
                                   unsigned int uinp_height )
{
    size_t uinl_len;
 
    uinl_len = m_sprintf( adsp_answer->chrc_answer + adsp_answer->inc_len,
                          HTML5_ANSWER_LEN - adsp_answer->inc_len,
                          "cvs.setSize(%u,%u);",
                          uinp_width, uinp_height );
    if ( uinl_len < 1 ){ return FALSE; }
    adsp_answer->inc_len += uinl_len;

    return TRUE;
} /* end of m_c2d_set_window_size */


/**
 * private function m_sprintf
 *  fill a buffer in printf style
 *
 * @param[in/out]   char        *achp_out       output buffer
 * @param[in]       size_t      uinp_maxlen     maximal length
 * @param[in]       const char  *achp_format    printf style format string
 * @return          size_t                      written bytes
*/
extern size_t m_sprintf( char *achp_out, size_t uinp_maxlen,
                         const char *achp_format, ...        )
{
    int     inl_written;                        /* written bytes         */
    va_list dsl_args;                           /* argument list         */

    va_start( dsl_args, achp_format );
    inl_written = vsnprintf( achp_out, uinp_maxlen, achp_format, dsl_args );
    va_end( dsl_args );
    if (    inl_written < 0
         || inl_written > (int)uinp_maxlen ) {
        return 0;
    }
    return (size_t)inl_written;
} /* end of m_sprintf */


/**
 * public function m_start_drawing
 *  create a new drawing command packet
 *
 * @param[in]   dsd_canvas_ctx  *adsp_ctx
 * @return      BOOL
*/
extern BOOL m_start_drawing( struct dsd_html5_answer *adsp_answer )
{
    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < dsg_json_object[0].inc_length ){ return FALSE; }

    strcat( adsp_answer->chrc_answer, dsg_json_object[0].achc_str);
    adsp_answer->inc_len += dsg_json_object[0].inc_length;

    return TRUE;
} /* end of m_start_drawing */



/**
 * public function m_finish_drawing
 *  finish a drawing command packet
 *
 * @return      BOOL
*/
extern BOOL m_finish_drawing( struct dsd_html5_answer *adsp_answer )
{
    if( ( HTML5_ANSWER_LEN - adsp_answer->inc_len ) < dsg_json_object[1].inc_length ){ return FALSE; }

    strcat( adsp_answer->chrc_answer + adsp_answer->inc_len, dsg_json_object[1].achc_str );
    adsp_answer->inc_len += dsg_json_object[1].inc_length;
        
    return TRUE;
} /* end of m_finish_drawing */


