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

bool cx_cxbe::dump_info(FILE *p_file)
{
    /*! sanity check */
    if(p_file == 0) { return false; }

    fprintf(p_file, "  __  __  __                  __           \n");
    fprintf(p_file, " |  ||__||  |--..----..--.--.|  |--..-----.\n");
    fprintf(p_file, " |  ||  ||  _  ||  __||_   _||  _  ||  -__|\n");
    fprintf(p_file, " |__||__||_____||____||__.__||_____||_____|\n");
    fprintf(p_file, "\n");
    fprintf(p_file, "Xbe File information generated by libcxbe (Version " CX_CXBE_VERSION ")\n");
    fprintf(p_file, "\n");
    fprintf(p_file, "Project : http://www.caustik.com/cxbx/\n");
    fprintf(p_file, "Source  : http://sourceforge.net/projects/cxbx/\n");
    fprintf(p_file, "\n");
    fprintf(p_file, "Title Name : \"%s\"\n", ascii_title);
    fprintf(p_file, "\n");
    fprintf(p_file, "Dumping Xbe Image Header...\n");
    fprintf(p_file, "\n");   
    fprintf(p_file, "Magic Number                     : XBEH\n");

    // print digital signature
    {
        int x, y;

        fprintf(p_file, "Digitial Signature               : <Hex Dump>");

        for(y=0;y<16;y++)
        {
            fprintf(p_file, "\n                                   ");

            for(x=0;x<16;x++)
            {
                fprintf(p_file, "%.02X", image_header.pbDigitalSignature[y*16+x]);
            }
        }

        fprintf(p_file, "\n                                   </Hex Dump>\n");
    }

    fprintf(p_file, "Base Address                     : 0x%.08X\n", image_header.dwBaseAddr);
    fprintf(p_file, "Size of Headers                  : 0x%.08X\n", image_header.dwSizeofHeaders);
    fprintf(p_file, "Size of Image                    : 0x%.08X\n", image_header.dwSizeofImage);
    fprintf(p_file, "Size of Image Header             : 0x%.08X\n", image_header.dwSizeofImageHeader);
    fprintf(p_file, "TimeDate Stamp                   : 0x%.08X (%s)\n", image_header.dwTimeDate, get_time_string(image_header.dwTimeDate).c_str());
    fprintf(p_file, "Certificate Address              : 0x%.08X\n", image_header.dwCertificateAddr);
    fprintf(p_file, "Number of Sections               : 0x%.08X\n", image_header.dwSections);
    fprintf(p_file, "Section Headers Address          : 0x%.08X\n", image_header.dwSectionHeadersAddr);

    /*! display init flags */
    {
        fprintf(p_file, "Init Flags                       : 0x%.08X ", image_header.u_init_flags.dwInitFlags);

        if(image_header.u_init_flags.init_flags.bMountUtilityDrive)
        {
            fprintf(p_file, "[Mount Utility Drive] ");
        }

        if(image_header.u_init_flags.init_flags.bFormatUtilityDrive)
        {
            fprintf(p_file, "[Format Utility Drive] ");
        }

        if(image_header.u_init_flags.init_flags.bLimit64MB)
        {
            fprintf(p_file, "[Limit Devkit Run Time Memory to 64MB] ");
        }

        if(!image_header.u_init_flags.init_flags.bDontSetupHarddisk)
        {
            fprintf(p_file, "[Setup Harddisk] ");
        }

        fprintf(p_file, "\n");
    }

    fprintf(p_file, "Entry Point                      : 0x%.08X (Retail: 0x%.08X, Debug: 0x%.08X)\n", image_header.dwEntryAddr, image_header.dwEntryAddr ^ CX_CXBE_XOR_KEY_EP_RETAIL, image_header.dwEntryAddr ^ CX_CXBE_XOR_KEY_EP_DEBUG);
    fprintf(p_file, "TLS Address                      : 0x%.08X\n", image_header.dwTLSAddr);
    fprintf(p_file, "(PE) Stack Commit                : 0x%.08X\n", image_header.dwPeStackCommit);
    fprintf(p_file, "(PE) Heap Reserve                : 0x%.08X\n", image_header.dwPeHeapReserve);
    fprintf(p_file, "(PE) Heap Commit                 : 0x%.08X\n", image_header.dwPeHeapCommit);
    fprintf(p_file, "(PE) Base Address                : 0x%.08X\n", image_header.dwPeBaseAddr);
    fprintf(p_file, "(PE) Size of Image               : 0x%.08X\n", image_header.dwPeSizeofImage);
    fprintf(p_file, "(PE) Checksum                    : 0x%.08X\n", image_header.dwPeChecksum);
    fprintf(p_file, "(PE) TimeDate Stamp              : 0x%.08X (%s)\n", image_header.dwPeTimeDate, get_time_string(image_header.dwPeTimeDate).c_str());
    fprintf(p_file, "Debug Pathname Address           : 0x%.08X (\"%s\")\n", image_header.dwDebugPathnameAddr, parse_ascii(image_header.dwDebugPathnameAddr).c_str());
    fprintf(p_file, "Debug Filename Address           : 0x%.08X (\"%s\")\n", image_header.dwDebugFilenameAddr, parse_ascii(image_header.dwDebugFilenameAddr).c_str());
    fprintf(p_file, "Debug Unicode filename Address   : 0x%.08X (\"%s\")\n", image_header.dwDebugUnicodeFilenameAddr, parse_utf16(image_header.dwDebugUnicodeFilenameAddr).c_str());
    fprintf(p_file, "Kernel Image Thunk Address       : 0x%.08X (Retail: 0x%.08X, Debug: 0x%.08X)\n", image_header.dwKernelImageThunkAddr, image_header.dwKernelImageThunkAddr ^ CX_CXBE_XOR_KEY_KT_RETAIL, image_header.dwKernelImageThunkAddr ^ CX_CXBE_XOR_KEY_KT_DEBUG);
    fprintf(p_file, "NonKernel Import Dir Address     : 0x%.08X\n", image_header.dwNonKernelImportDirAddr);
    fprintf(p_file, "Library Versions                 : 0x%.08X\n", image_header.dwLibraryVersions);
    fprintf(p_file, "Library Versions Address         : 0x%.08X\n", image_header.dwLibraryVersionsAddr);
    fprintf(p_file, "Kernel Library Version Address   : 0x%.08X\n", image_header.dwKernelLibraryVersionAddr);
    fprintf(p_file, "XAPI Library Version Address     : 0x%.08X\n", image_header.dwXAPILibraryVersionAddr);
    fprintf(p_file, "Logo Bitmap Address              : 0x%.08X\n", image_header.dwLogoBitmapAddr);
    fprintf(p_file, "Logo Bitmap Size                 : 0x%.08X\n", image_header.dwSizeofLogoBitmap);
    fprintf(p_file, "\n");
    fprintf(p_file, "Dumping Xbe Certificate...\n");
    fprintf(p_file, "\n");
    fprintf(p_file, "Size of Certificate              : 0x%.08X\n", certificate.dwSize);
    fprintf(p_file, "TimeDate Stamp                   : 0x%.08X (%s)\n", certificate.dwTimeDate, get_time_string(certificate.dwTimeDate).c_str());
    fprintf(p_file, "Title ID                         : 0x%.08X\n", certificate.dwTitleId);
    fprintf(p_file, "Title Name                       : 0x%.08X (\"%s\")\n", certificate.wszTitleName, ascii_title);

    // print alternate title IDs
    {
        fprintf(p_file, "Alternate Titles IDs             : ");

        uint32 v;

        for(v=0;v<0x10;v++)
        {
            if(v != 0)
            {
                fprintf(p_file, "                                   ");
            }

            fprintf(p_file, "0x%.08X", certificate.dwAlternateTitleId[v]);

            if(v != 0x0F)
            {
                fprintf(p_file, "\n");
            }
        }

        fprintf(p_file, "\n");
    }

    fprintf(p_file, "Allowed Media                    : 0x%.08X\n", certificate.dwAllowedMedia);
    fprintf(p_file, "Game Region                      : 0x%.08X\n", certificate.dwGameRegion);
    fprintf(p_file, "Game Ratings                     : 0x%.08X\n", certificate.dwGameRatings);
    fprintf(p_file, "Disk Number                      : 0x%.08X\n", certificate.dwDiskNumber);
    fprintf(p_file, "Version                          : 0x%.08X\n", certificate.dwVersion);

    /*! print LAN key */
    {
        fprintf(p_file, "LAN Key                          : ");

        uint32 v;

        for(v=0;v<16;v++)
        {
            fprintf(p_file, "%.02X", certificate.bzLanKey[v]);
        }

        fprintf(p_file, "\n");
    }

    /*! print signature key */
    {
        fprintf(p_file, "Signature Key                    : ");

        uint32 v;        

        for(v=0;v<16;v++)
        {
            fprintf(p_file, "%.02X", certificate.bzSignatureKey[v]);
        }

        fprintf(p_file, "\n");
    }

    /*! print alternate signature keys */
    {
        fprintf(p_file, "Title Alternate Signature Keys   : <Hex Dump>");

        uint32 y, x;

        for(y=0;y<16;y++)
        {
            fprintf(p_file, "\n                                   ");

            for(x=0;x<16;x++)
            {
                fprintf(p_file, "%.02X", certificate.bzTitleAlternateSignatureKey[y][x]);
            }
        }

        fprintf(p_file, "\n                                   </Hex Dump>\n");
    }

    fprintf(p_file, "\n");   
    fprintf(p_file, "Dumping Xbe Section Headers...\n");
    fprintf(p_file, "\n");   

    /*! print section headers */
    {
        uint32 v;

        for(v=0;v<image_header.dwSections;v++)
        {
            fprintf(p_file, "Section Name                     : 0x%.08X (\"%s\")\n", p_section_header[v].dwSectionNameAddr, section_name[v]);

            /*! print section flags */
            {
                fprintf(p_file, "Flags                            : 0x%.08X ", p_section_header[v].u_flags.dwFlags);

                if(p_section_header[v].u_flags.flags.bWritable)
                {
                    fprintf(p_file, "(Writable) ");
                }

                if(p_section_header[v].u_flags.flags.bPreload)
                {
                    fprintf(p_file, "(Preload) ");
                }

                if(p_section_header[v].u_flags.flags.bExecutable)
                {
                    fprintf(p_file, "(Executable) ");
                }

                if(p_section_header[v].u_flags.flags.bInsertedFile)
                {
                    fprintf(p_file, "(Inserted File) ");
                }

                if(p_section_header[v].u_flags.flags.bHeadPageRO)
                {
                    fprintf(p_file, "(Head Page RO) ");
                }

                if(p_section_header[v].u_flags.flags.bTailPageRO)
                {
                    fprintf(p_file, "(Tail Page RO) ");
                }

                fprintf(p_file, "\n");
            }

            fprintf(p_file, "Virtual Address                  : 0x%.08X\n", p_section_header[v].dwVirtualAddr);
            fprintf(p_file, "Virtual Size                     : 0x%.08X\n", p_section_header[v].dwVirtualSize);
            fprintf(p_file, "Raw Address                      : 0x%.08X\n", p_section_header[v].dwRawAddr);
            fprintf(p_file, "Size of Raw                      : 0x%.08X\n", p_section_header[v].dwSizeofRaw);
            fprintf(p_file, "Section Name Address             : 0x%.08X\n", p_section_header[v].dwSectionNameAddr);
            fprintf(p_file, "Section Reference Count          : 0x%.08X\n", p_section_header[v].dwSectionRefCount);
            fprintf(p_file, "Head Shared Reference Count Addr : 0x%.08X\n", p_section_header[v].dwHeadSharedRefCountAddr);
            fprintf(p_file, "Tail Shared Reference Count Addr : 0x%.08X\n", p_section_header[v].dwTailSharedRefCountAddr);

            /*! print section digest */
            {
                fprintf(p_file, "Section Digest                   : ");

                uint32 s;

                for(s=0;s<20;s++)
                {
                    fprintf(p_file, "%.02X", p_section_header[v].bzSectionDigest[s]);
                }

                fprintf(p_file, "\n");
            }

            fprintf(p_file, "\n");
        }
    }

    fprintf(p_file, "Dumping Xbe Library Versions...\n");
    fprintf(p_file, "\n");   

    /*! print xbe library versions */
    {
        if( (p_library_version == 0) || (image_header.dwLibraryVersions == 0) )
        {
            fprintf(p_file, "(This Xbe contains no Library Versions)\n");
            fprintf(p_file, "\n");
        }
        else
        {
            uint32 v;

            for(v=0;v<image_header.dwLibraryVersions;v++)
            {
                char library_name[9] = { 0 };

                strncpy(library_name, p_library_version[v].szName, 8);

                fprintf(p_file, "Library Name                     : %s\n", library_name);
                fprintf(p_file, "Version                          : %d.%d.%d\n", p_library_version[v].wMajorVersion, p_library_version[v].wMinorVersion, p_library_version[v].wBuildVersion);
 
                /*! print xbe library version flags */
                {
                    fprintf(p_file, "Flags                            : ");

                    fprintf(p_file, "QFEVersion : 0x%.04X, ", p_library_version[v].u_flags.flags.QFEVersion);

                    if(p_library_version[v].u_flags.flags.bDebugBuild)
                    {
                        fprintf(p_file, "Debug, ");
                    }
                    else
                    {
                        fprintf(p_file, "Retail, ");
                    }

                    switch(p_library_version[v].u_flags.flags.Approved)
                    {
                        case 0:
                            fprintf(p_file, "Unapproved");
                            break;
                        case 1:
                            fprintf(p_file, "Possibly Approved");
                            break;
                        case 2:
                            fprintf(p_file, "Approved");
                            break;
                    }

                    fprintf(p_file, "\n");
                }

                fprintf(p_file, "\n");
            }
        }
    }

    fprintf(p_file, "Dumping Thread Local Storage information...\n");
    fprintf(p_file, "\n");   

    /*! print thread local storage information */
    if(p_tls != 0)
    {
        fprintf(p_file, "Data Start Address               : 0x%.08X\n", p_tls->dwDataStartAddr);
        fprintf(p_file, "Data End Address                 : 0x%.08X\n", p_tls->dwDataEndAddr);
        fprintf(p_file, "TLS Index Address                : 0x%.08X\n", p_tls->dwTLSIndexAddr);
        fprintf(p_file, "TLS Callback Address             : 0x%.08X\n", p_tls->dwTLSCallbackAddr);
        fprintf(p_file, "Size of Zero Fill                : 0x%.08X\n", p_tls->dwSizeofZeroFill);
        fprintf(p_file, "Characteristics                  : 0x%.08X\n", p_tls->dwCharacteristics);
    }
    else
    {
        fprintf(p_file, "(This Xbe contains no Thread Local Storage information)\n");
    }

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
    /*! @todo verify this is the realistic max */
    static const int max_raw_size = 40;

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

