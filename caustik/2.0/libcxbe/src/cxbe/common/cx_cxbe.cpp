/******************************************************************************
 *
 * Caustik's Xbox Executable Library Project
 *
 * Copyright (c) 2007, Aaron "Caustik" Robinson
 * All rights reserved.
 * 
 * File := cx_cxbe.cpp
 * Desc := Xbox Executable class
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, 
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice, 
 *   this list of conditions and the following disclaimer in the documentation 
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Aaron "Caustik" Robinson nor the names of its 
 *   contributors may be used to endorse or promote products derived from this 
 *   software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 *   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
 * 
 *****************************************************************************/

#include "cxbe.h"

#include <time.h>

cx_cxbe::cx_cxbe()
{
    p_extra_bytes = 0;
    p_section_header = 0;
    p_section = 0;
    section_name = 0;

    p_library_version = 0;
    p_library_version_kernel = 0;
    p_library_version_xapi = 0;

    p_tls = 0;

    close();
}

cx_cxbe::~cx_cxbe()
{
    close();
}

bool cx_cxbe::open(const wchar_t *file_name)
{
    bool ret = false, chk = true;

    rp_debug_trace("cx_cxbe::open(\"%ls\")\n", file_name);

    rp_file xbe_file;

    /*! validate file opened */
    if(!xbe_file.open(file_name))
    {
        rp_debug_error("cx_cxbe::open : Unable to open \"%ls\".\n", file_name);
        goto cleanup;
    }

    rp_debug_trace("cx_cxbe::open : reading xbe image header...\n");

    /*! read xbe image header */
    {
        chk |= xbe_file.get_uint32(&image_header.dwMagic);
        chk |= xbe_file.get_barray(image_header.pbDigitalSignature, 256);
        chk |= xbe_file.get_uint32(&image_header.dwBaseAddr);
        chk |= xbe_file.get_uint32(&image_header.dwSizeofHeaders);
        chk |= xbe_file.get_uint32(&image_header.dwSizeofImage);
        chk |= xbe_file.get_uint32(&image_header.dwSizeofImageHeader);
        chk |= xbe_file.get_uint32(&image_header.dwTimeDate);
        chk |= xbe_file.get_uint32(&image_header.dwCertificateAddr);
        chk |= xbe_file.get_uint32(&image_header.dwSections);
        chk |= xbe_file.get_uint32(&image_header.dwSectionHeadersAddr);
        chk |= xbe_file.get_uint32(&image_header.u_init_flags.dwInitFlags);
        chk |= xbe_file.get_uint32(&image_header.dwEntryAddr);
        chk |= xbe_file.get_uint32(&image_header.dwTLSAddr);
        chk |= xbe_file.get_uint32(&image_header.dwPeStackCommit);
        chk |= xbe_file.get_uint32(&image_header.dwPeHeapReserve);
        chk |= xbe_file.get_uint32(&image_header.dwPeHeapCommit);
        chk |= xbe_file.get_uint32(&image_header.dwPeBaseAddr);
        chk |= xbe_file.get_uint32(&image_header.dwPeSizeofImage);
        chk |= xbe_file.get_uint32(&image_header.dwPeChecksum);
        chk |= xbe_file.get_uint32(&image_header.dwPeTimeDate);
        chk |= xbe_file.get_uint32(&image_header.dwDebugPathnameAddr);
        chk |= xbe_file.get_uint32(&image_header.dwDebugFilenameAddr);
        chk |= xbe_file.get_uint32(&image_header.dwDebugUnicodeFilenameAddr);
        chk |= xbe_file.get_uint32(&image_header.dwKernelImageThunkAddr);
        chk |= xbe_file.get_uint32(&image_header.dwNonKernelImportDirAddr);
        chk |= xbe_file.get_uint32(&image_header.dwLibraryVersions);
        chk |= xbe_file.get_uint32(&image_header.dwLibraryVersionsAddr);
        chk |= xbe_file.get_uint32(&image_header.dwKernelLibraryVersionAddr);
        chk |= xbe_file.get_uint32(&image_header.dwXAPILibraryVersionAddr);
        chk |= xbe_file.get_uint32(&image_header.dwLogoBitmapAddr);
        chk |= xbe_file.get_uint32(&image_header.dwSizeofLogoBitmap);

        if(!chk)
        {
            rp_debug_error("cx_cxbe::open : Unable to read image header.\n");
            goto cleanup;
        }

        /*! validate magic number */
        if(image_header.dwMagic != rp_binary::four_cc("XBEH"))
        {
            rp_debug_error("cx_cxbe::open : Invalid magic number.\n");
            goto cleanup;
        }
    }

    rp_debug_trace("cx_cxbe::open : reading xbe image header extra bytes...\n");

    /*! read xbe image header extra bytes */
    {
        uint32 ex_size = rp_math::round_up(image_header.dwSizeofHeaders, 0x1000) - CX_CXBE_SIZEOF_IMAGE_HEADER;

        p_extra_bytes = new uint08[ex_size];

        /*! validate memory allocation */
        if(p_extra_bytes == 0)
        {
            rp_debug_error("cx_cxbe::open : Unable to allocate memory for image header extra bytes.\n");
            goto cleanup;
        }

        /*! read raw bytes from xbe_file */
        if(!xbe_file.get_barray(p_extra_bytes, ex_size))
        {
            rp_debug_error("cx_cxbe::open : Unable to read image header extra bytes.\n");
            goto cleanup;
        }
    }

    rp_debug_trace("cx_cxbe::open : reading xbe certificate...\n");

    /*! read xbe certificate */
    {
        int v;

        if(!xbe_file.seek_abs(image_header.dwCertificateAddr - image_header.dwBaseAddr))
        {
            rp_debug_error("cx_cxbe::open : Unable to seek to xbe certificate.\n");
            goto cleanup;
        }

        chk |= xbe_file.get_uint32(&certificate.dwSize);
        chk |= xbe_file.get_uint32(&certificate.dwTimeDate);
        chk |= xbe_file.get_uint32(&certificate.dwTitleId);
        /*! @todo support wchar_t more correctly by converting from UTF-16 to wchar_t */
        chk |= xbe_file.get_barray((uint08*)certificate.wszTitleName, 40*sizeof(wchar_t));
        /*! @todo support uint32 arrays? */
        chk |= xbe_file.get_barray((uint08*)certificate.dwAlternateTitleId, 0x10*sizeof(uint32));
        chk |= xbe_file.get_uint32(&certificate.dwAllowedMedia);
        chk |= xbe_file.get_uint32(&certificate.dwGameRegion);
        chk |= xbe_file.get_uint32(&certificate.dwGameRatings);
        chk |= xbe_file.get_uint32(&certificate.dwDiskNumber);
        chk |= xbe_file.get_uint32(&certificate.dwVersion);
        chk |= xbe_file.get_barray(certificate.bzLanKey, 16);
        chk |= xbe_file.get_barray(certificate.bzSignatureKey, 16);

        for(v=0;v<16;v++) { chk |= xbe_file.get_barray(certificate.bzTitleAlternateSignatureKey[v], 16); }

        if(!chk)
        {
            rp_debug_error("cx_cxbe::open : Unable to read image header.\n");
            goto cleanup;
        }

        /*! convert ascii title */
        wcstombs(ascii_title, certificate.wszTitleName, sizeof(ascii_title)-1);
    }

    rp_debug_trace("cx_cxbe::open : reading xbe section headers...\n");

    /*! read xbe section headers */
    {
        if(!xbe_file.seek_abs(image_header.dwSectionHeadersAddr - image_header.dwBaseAddr))
        {
            rp_debug_error("cx_cxbe::open : Unable to seek to xbe section headers.\n");
            goto cleanup;
        }

        p_section_header = new _section_header[image_header.dwSections];

        if(p_section_header == 0)
        {
            rp_debug_error("cx_cxbe::open : Unable to allocate section headers [%d].\n", image_header.dwSections);
            goto cleanup;
        }

        uint32 v;

        for(v=0;v<image_header.dwSections;v++)
        {
            rp_debug_trace("cx_cxbe::open : reading xbe section header %d...\n", v);

            chk |= xbe_file.get_uint32(&p_section_header[v].u_flags.dwFlags);
            chk |= xbe_file.get_uint32(&p_section_header[v].dwVirtualAddr);
            chk |= xbe_file.get_uint32(&p_section_header[v].dwVirtualSize);
            chk |= xbe_file.get_uint32(&p_section_header[v].dwRawAddr);
            chk |= xbe_file.get_uint32(&p_section_header[v].dwSizeofRaw);
            chk |= xbe_file.get_uint32(&p_section_header[v].dwSectionNameAddr);
            chk |= xbe_file.get_uint32(&p_section_header[v].dwSectionRefCount);
            chk |= xbe_file.get_uint32(&p_section_header[v].dwHeadSharedRefCountAddr);
            chk |= xbe_file.get_uint32(&p_section_header[v].dwTailSharedRefCountAddr);
            chk |= xbe_file.get_barray(p_section_header[v].bzSectionDigest, 20);
            
            if(!chk)
            {
                rp_debug_error("cx_cxbe::open : Unable to read xbe section header %d.\n", v);
                goto cleanup;
            }
        }
    }

    rp_debug_trace("cx_cxbe::open : reading xbe sections...\n");

    /*! read xbe sections */
    {
        p_section = new uint08*[image_header.dwSections];

        if(p_section == 0)
        {
            rp_debug_error("cx_cxbe::open : Unable to allocate sections [%d].\n", image_header.dwSections);
            goto cleanup;
        }

        memset(p_section, 0, image_header.dwSections*sizeof(uint08*));

        uint32 v;

        for(v=0;v<image_header.dwSections;v++)
        {
            rp_debug_trace("cx_cxbe::open : reading xbe section %d...\n", v);

            uint32 raw_addr = p_section_header[v].dwRawAddr;
            uint32 raw_size = p_section_header[v].dwSizeofRaw;

            /*! handle zero sized section */
            if(raw_size == 0) { continue; }

            p_section[v] = new uint08[raw_size];

            if(p_section[v] == 0)
            {
                rp_debug_error("cx_cxbe::open : Unable to allocate section %d.\n", v);
                goto cleanup;
            }

            if(!xbe_file.seek_abs(raw_addr))
            {
                rp_debug_error("cx_cxbe::open : Unable to seek to section %d.\n", v);
                goto cleanup;
            }

            if(!xbe_file.get_barray(p_section[v], raw_size))
            {
                rp_debug_error("cx_cxbe::open : Unable to read section %d.\n", v);
                goto cleanup;
            }
        }
    }

    rp_debug_trace("cx_cxbe::open : reading xbe section names...\n");

    /*! read xbe section names */
    {
        section_name = new char[image_header.dwSections][9];

        uint32 v;

        for(v=0;v<image_header.dwSections;v++)
        {
            rp_debug_trace("cx_cxbe::open : reading xbe section %d name...\n", v);

            const char *cur_name = (const char*)get_addr(p_section_header[v].dwSectionNameAddr);

            memset(section_name[v], 0, sizeof(char)*9);

            strncpy(section_name[v], (cur_name != 0) ? cur_name : "", 8);
        }
    }

    rp_debug_trace("cx_cxbe::open : reading xbe library versions...\n");

    /*! read xbe library versions */
    if(image_header.dwLibraryVersionsAddr != 0)
    {
        if(!xbe_file.seek_abs(image_header.dwLibraryVersionsAddr - image_header.dwBaseAddr))
        {
            rp_debug_error("cx_cxbe::open : Unable to seek to xbe library versions.\n");
            goto cleanup;
        }

        p_library_version = new _library_version[image_header.dwLibraryVersions];

        if(p_library_version == 0)
        {
            rp_debug_error("cx_cxbe::open : Unable to allocate library versions [%d].\n", image_header.dwLibraryVersions);
            goto cleanup;
        }

        uint32 v;

        for(v=0;v<image_header.dwLibraryVersions;v++)
        {
            rp_debug_trace("cx_cxbe::open : reading xbe library version %d...\n", v);

            chk = parse_library_version(&xbe_file, &p_library_version[v]);

            if(!chk)
            {
                rp_debug_error("cx_cxbe::open : Unable to read xbe library version %d.\n", v);
                goto cleanup;
            }
        }

        /*! read xbe kernel library version */
        {
            if(image_header.dwKernelLibraryVersionAddr == 0)
            {
                rp_debug_error("cx_cxbe::open : Unable to locate kernel library version.\n");
                goto cleanup;
            }
            
            if(!xbe_file.seek_abs(image_header.dwKernelLibraryVersionAddr - image_header.dwBaseAddr))
            {
                rp_debug_error("cx_cxbe::open : Unable to seek to xbe kernel library versions.\n");
                goto cleanup;
            }

            p_library_version_kernel = new _library_version;

            if(p_library_version == 0)
            {
                rp_debug_error("cx_cxbe::open : Unable to allocate kernel library version.\n");
                goto cleanup;
            }

            chk = parse_library_version(&xbe_file, p_library_version_kernel);

            if(!chk)
            {
                rp_debug_error("cx_cxbe::open : Unable to read xbe kernel library version.\n");
                goto cleanup;
            }
        }

        /*! read xbe XAPI library version */
        {
            if(image_header.dwXAPILibraryVersionAddr == 0)
            {
                rp_debug_error("cx_cxbe::open : Unable to locate XAPI library version.\n");
                goto cleanup;
            }
            
            if(!xbe_file.seek_abs(image_header.dwXAPILibraryVersionAddr - image_header.dwBaseAddr))
            {
                rp_debug_error("cx_cxbe::open : Unable to seek to xbe XAPI library versions.\n");
                goto cleanup;
            }

            p_library_version_xapi = new _library_version;

            if(p_library_version == 0)
            {
                rp_debug_error("cx_cxbe::open : Unable to allocate XAPI library version.\n");
                goto cleanup;
            }

            chk = parse_library_version(&xbe_file, p_library_version_xapi);

            if(!chk)
            {
                rp_debug_error("cx_cxbe::open : Unable to read xbe XAPI library version.\n");
                goto cleanup;
            }
        }
    }

    rp_debug_trace("cx_cxbe::open : reading xbe thread local storage information...\n");

    /*! read xbe thread local storage information */
    if(image_header.dwTLSAddr != 0)
    {
        void *addr = get_addr(image_header.dwTLSAddr);

        if(addr == 0)
        {
            rp_debug_error("cx_cxbe::open : Unable to locate Thread Local Storage information.\n");
            goto cleanup;
        }

        p_tls = new _tls;

        if(p_tls == 0)
        {
            rp_debug_error("cx_cxbe::open : Unable to allocate Thread Local Storage information.\n");
            goto cleanup;
        }

        rp_binary parse(addr);

        chk |= parse.get_uint32(&p_tls->dwDataStartAddr);
        chk |= parse.get_uint32(&p_tls->dwDataEndAddr);
        chk |= parse.get_uint32(&p_tls->dwTLSIndexAddr);
        chk |= parse.get_uint32(&p_tls->dwTLSCallbackAddr);
        chk |= parse.get_uint32(&p_tls->dwSizeofZeroFill);
        chk |= parse.get_uint32(&p_tls->dwCharacteristics);
    }

    ret = true;

cleanup:

    xbe_file.close();

    return ret;
}

bool cx_cxbe::open(cx_cexe *p_cexe, const char *title, bool is_retail)
{
    return false;
}

bool cx_cxbe::close()
{
    if(p_tls != 0)
    {
        delete p_tls;
        p_tls = 0;
    }

    if(p_library_version_xapi != 0)
    {
        delete p_library_version_xapi;
        p_library_version_xapi = 0;
    }

    if(p_library_version_kernel != 0)
    {
        delete p_library_version_kernel;
        p_library_version_kernel = 0;
    }

    if(p_library_version != 0)
    {
        delete[] p_library_version;
        p_library_version = 0;
    }

    if(section_name != 0)
    {
        delete[] section_name;
        section_name = 0;
    }

    if(p_section != 0)
    {
        uint32 v;

        for(v=0;v<image_header.dwSections;v++)
        {
            delete[] p_section[v];
            p_section[v] = 0;
        }

        delete[] p_section;
    }

    if(p_section_header != 0)
    {
        delete[] p_section_header;
        p_section_header = 0;
    }

    if(p_extra_bytes != 0)
    {
        delete[] p_extra_bytes;
        p_extra_bytes = 0;
    }

    memset(&image_header, 0, sizeof(image_header));
    memset(&certificate, 0, sizeof(certificate));
    memset(ascii_title, 0, sizeof(ascii_title));

    return true;
}

void *cx_cxbe::get_addr(uint32 virt_addr)
{
    /*! calculate offset from base address */
    uint32 offset = virt_addr - image_header.dwBaseAddr;

    /*! calculate offset into image header, if appropriate */
    if(offset < CX_CXBE_SIZEOF_IMAGE_HEADER)
    {
        rp_debug_error("cx_cxbe::open : Need cross-platform translation table for image header virtual address.\n");
        return 0;
    }

    /*! calculate offset into image header extra bytes */
    if(offset < image_header.dwSizeofHeaders)
    {
        return &p_extra_bytes[offset - CX_CXBE_SIZEOF_IMAGE_HEADER];
    }

    /*! calculate offset into an xbe section */
    {
        uint32 v;

        for(v=0;v<image_header.dwSections;v++)
        {
            uint32 sect_virt_addr = p_section_header[v].dwVirtualAddr;
            uint32 sect_virt_size = p_section_header[v].dwVirtualSize;

            /*! validate virt_addr fits within this section's virtual address space */
            if( (virt_addr >= sect_virt_addr) && (virt_addr < (sect_virt_addr + sect_virt_size)) )
            {
                /*! return appropriate offset into raw section data */
                return &p_section[v][sect_virt_addr - virt_addr];
            }
        }
    }

    return 0;
}

std::string cx_cxbe::get_time_string(uint32 time_val)
{
    std::string str = "";

    time_t val = (time_t)time_val;

    const char *ctime_str = ctime((time_t*)&val);

    if(ctime_str != 0)
    {
        str = ctime_str;

        int v;

        for(v=0;str[v] != '\n';v++);

        str[v] = '\0';
    }

    return str;
}

std::string cx_cxbe::parse_ascii(uint32 virt_addr)
{
    /*! @todo add proper UTF-16 parsing */
    char *virt_str = (char*)get_addr(virt_addr);

    /*! convert string, if located */
    if(virt_str != 0) { return virt_str; }

    return "";
}

std::string cx_cxbe::parse_utf16(uint32 virt_addr)
{
    /*! @todo verify this is the realistic max */
    static const int max_raw_size = 40;

    /*! @todo add proper UTF-16 parsing */
    wchar_t *virt_str = (wchar_t*)get_addr(virt_addr);

    /*! convert string, if located */
    if(virt_str != 0)
    {
        rp_auto_malloc<char> raw_str(max_raw_size);

        memset(raw_str, 0, max_raw_size*sizeof(char));

        wcstombs(raw_str, virt_str, max_raw_size-1);

        return raw_str.get_ptr();
    }

    return "";
}

bool cx_cxbe::parse_library_version(rp_file *p_xbe_file, _library_version *p_library_version)
{
    /*! sanity check */
    if(p_xbe_file == 0) { return false; }

    bool chk = true;

    chk |= p_xbe_file->get_barray((uint08*)p_library_version->szName, 8);
    chk |= p_xbe_file->get_uint16(&p_library_version->wMajorVersion);
    chk |= p_xbe_file->get_uint16(&p_library_version->wMinorVersion);
    chk |= p_xbe_file->get_uint16(&p_library_version->wBuildVersion);
    chk |= p_xbe_file->get_uint16(&p_library_version->u_flags.wFlags);

    return chk;
}

