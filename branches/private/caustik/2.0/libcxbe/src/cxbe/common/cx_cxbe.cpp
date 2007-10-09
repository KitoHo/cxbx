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

cx_cxbe::cx_cxbe()
{
    memset(&image_header, 0, sizeof(image_header));
    p_extra_bytes = 0;
}

cx_cxbe::~cx_cxbe()
{
    close();
}

bool cx_cxbe::open(const wchar_t *file_name)
{
    bool ret = false;

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
        ret |= xbe_file.get_uint32(&image_header.dwMagic);
        ret |= xbe_file.get_barray(image_header.pbDigitalSignature, 256);
        ret |= xbe_file.get_uint32(&image_header.dwBaseAddr);
        ret |= xbe_file.get_uint32(&image_header.dwSizeofHeaders);
        ret |= xbe_file.get_uint32(&image_header.dwSizeofImage);
        ret |= xbe_file.get_uint32(&image_header.dwSizeofImageHeader);
        ret |= xbe_file.get_uint32(&image_header.dwTimeDate);
        ret |= xbe_file.get_uint32(&image_header.dwCertificateAddr);
        ret |= xbe_file.get_uint32(&image_header.dwSections);
        ret |= xbe_file.get_uint32(&image_header.dwSectionHeadersAddr);
        ret |= xbe_file.get_uint32(&image_header.u_init_flags.dwInitFlags);
        ret |= xbe_file.get_uint32(&image_header.dwEntryAddr);
        ret |= xbe_file.get_uint32(&image_header.dwTLSAddr);
        ret |= xbe_file.get_uint32(&image_header.dwPeStackCommit);
        ret |= xbe_file.get_uint32(&image_header.dwPeHeapReserve);
        ret |= xbe_file.get_uint32(&image_header.dwPeHeapCommit);
        ret |= xbe_file.get_uint32(&image_header.dwPeBaseAddr);
        ret |= xbe_file.get_uint32(&image_header.dwPeSizeofImage);
        ret |= xbe_file.get_uint32(&image_header.dwPeChecksum);
        ret |= xbe_file.get_uint32(&image_header.dwPeTimeDate);
        ret |= xbe_file.get_uint32(&image_header.dwDebugPathnameAddr);
        ret |= xbe_file.get_uint32(&image_header.dwDebugFilenameAddr);
        ret |= xbe_file.get_uint32(&image_header.dwDebugUnicodeFilenameAddr);
        ret |= xbe_file.get_uint32(&image_header.dwKernelImageThunkAddr);
        ret |= xbe_file.get_uint32(&image_header.dwNonKernelImportDirAddr);
        ret |= xbe_file.get_uint32(&image_header.dwLibraryVersions);
        ret |= xbe_file.get_uint32(&image_header.dwLibraryVersionsAddr);
        ret |= xbe_file.get_uint32(&image_header.dwKernelLibraryVersionAddr);
        ret |= xbe_file.get_uint32(&image_header.dwXAPILibraryVersionAddr);
        ret |= xbe_file.get_uint32(&image_header.dwLogoBitmapAddr);
        ret |= xbe_file.get_uint32(&image_header.dwSizeofLogoBitmap);

        if(!ret)
        {
            rp_debug_error("cx_cxbe::open : Unable to read image header.\n");
            goto cleanup;
        }
    }

    /*! read xbe image header extra bytes */
    {
        uint32 ex_size = rp_math::round_up(image_header.dwSizeofHeaders, 0x1000) - CX_CXBE_SIZEOF_IMAGE_HEADER;

        p_extra_bytes = new uint08[ex_size];

        if(p_extra_bytes == 0)
        {
            rp_debug_error("cx_cxbe::open : Unable to allocate memory for image header extra bytes.\n");
            goto cleanup;
        }

        if(!xbe_file.get_barray(p_extra_bytes, ex_size))
        {
            rp_debug_error("cx_cxbe::open : Unable to read image header extra bytes.\n");
            goto cleanup;
        }
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

    return true;
}

