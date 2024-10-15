class CSE
{
public:
    static _se_translator_function MapSEtoCE()
    {
        return _set_se_translator(TranslateSEtoCE);
    }

    static void UnmapSEtoCE(_se_translator_function av_orgtranslator)
    {
        _set_se_translator(av_orgtranslator);
    }

private:

    CSE(EXCEPTION_POINTERS* adsExcepPointers)
    {
        m_dsExcepPointers = *adsExcepPointers;
        m_hl_toplevelexceptionfilter(adsExcepPointers);
    }

    static void _cdecl TranslateSEtoCE(UINT /*ulEC*/,EXCEPTION_POINTERS* adsExcepPointers)
    {
        throw CSE(adsExcepPointers);
    }

    EXCEPTION_POINTERS m_dsExcepPointers;

};
