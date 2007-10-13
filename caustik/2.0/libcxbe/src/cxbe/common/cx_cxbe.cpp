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

    rp_debug_trace("cx_cxbe::open : reading image header...\n");

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
        wcstombs(ascii_title, certificate.wszTitleName, 40);
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
    fprintf(p_file, "<Xbe Image Header>\n");
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

    /*! @todo add the rest after we can access the section headers */

    fprintf(p_file, "\n");
    fprintf(p_file, "</Xbe Image Header>\n");

    return true;
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

