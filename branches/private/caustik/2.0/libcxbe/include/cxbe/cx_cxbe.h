/******************************************************************************
 * 
 * Caustik's Xbox Executable Library Project
 *
 * Copyright (c) 2007, Aaron "Caustik" Robinson
 * All rights reserved.
 * 
 * File := cx_cxbe.h
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
 *   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 *****************************************************************************/

#ifndef CX_CXBE_H
#define CX_CXBE_H

#include <regplat.h>

/*! @brief Xbox Executable class. */
class cx_cxbe
{
    public:

        cx_cxbe();
        virtual ~cx_cxbe();

        /*! load from the specified Xbe file */
        bool open(const wchar_t *file_name);

        /*! load from the specified cexe instance */
        bool open(cx_cexe *p_cexe, const char *title, bool is_retail);

        /*! close the currently loaded file */
        bool close();

        /*! dump xbe information to the specified file*/
        bool dump_info(FILE *p_file);

    private:

        /*! xbe image header */
        struct _image_header
        {
            uint32 dwMagic;                             /*!< 0x0000 - magic number [should be "XBEH"] */
            uint08 pbDigitalSignature[256];             /*!< 0x0004 - digital signature */
            uint32 dwBaseAddr;                          /*!< 0x0104 - base address */
            uint32 dwSizeofHeaders;                     /*!< 0x0108 - size of headers */
            uint32 dwSizeofImage;                       /*!< 0x010C - size of image */
            uint32 dwSizeofImageHeader;                 /*!< 0x0110 - size of image header */
            uint32 dwTimeDate;                          /*!< 0x0114 - timedate stamp */
            uint32 dwCertificateAddr;                   /*!< 0x0118 - certificate address */
            uint32 dwSections;                          /*!< 0x011C - number of sections */
            uint32 dwSectionHeadersAddr;                /*!< 0x0120 - section headers address */

            union _u_init_flags
            {
                struct _init_flags                      /*!< 0x0124 - initialization flags */
                {
                    uint32 bMountUtilityDrive   : 1;    /*!< mount utility drive flag */
                    uint32 bFormatUtilityDrive  : 1;    /*!< format utility drive flag */
                    uint32 bLimit64MB           : 1;    /*!< limit development kit run time memory to 64mb flag */
                    uint32 bDontSetupHarddisk   : 1;    /*!< don't setup hard disk flag */
                    uint32 Unused               : 4;    /*!< unused (or unknown) */
                    uint32 Unused_b1            : 8;    /*!< unused (or unknown) */
                    uint32 Unused_b2            : 8;    /*!< unused (or unknown) */
                    uint32 Unused_b3            : 8;    /*!< unused (or unknown) */
                }
                init_flags;

                uint32 dwInitFlags;
            }
            u_init_flags;

            uint32 dwEntryAddr;                         /*!< 0x0128 - entry point address */
            uint32 dwTLSAddr;                           /*!< 0x012C - thread local storage directory address */
            uint32 dwPeStackCommit;                     /*!< 0x0130 - size of stack commit */
            uint32 dwPeHeapReserve;                     /*!< 0x0134 - size of heap reserve */
            uint32 dwPeHeapCommit;                      /*!< 0x0138 - size of heap commit */
            uint32 dwPeBaseAddr;                        /*!< 0x013C - original base address */
            uint32 dwPeSizeofImage;                     /*!< 0x0140 - size of original image */
            uint32 dwPeChecksum;                        /*!< 0x0144 - original checksum */
            uint32 dwPeTimeDate;                        /*!< 0x0148 - original timedate stamp */
            uint32 dwDebugPathnameAddr;                 /*!< 0x014C - debug pathname address */
            uint32 dwDebugFilenameAddr;                 /*!< 0x0150 - debug filename address */
            uint32 dwDebugUnicodeFilenameAddr;          /*!< 0x0154 - debug unicode filename address */
            uint32 dwKernelImageThunkAddr;              /*!< 0x0158 - kernel image thunk address */
            uint32 dwNonKernelImportDirAddr;            /*!< 0x015C - non kernel import directory address */
            uint32 dwLibraryVersions;                   /*!< 0x0160 - number of library versions */
            uint32 dwLibraryVersionsAddr;               /*!< 0x0164 - library versions address */
            uint32 dwKernelLibraryVersionAddr;          /*!< 0x0168 - kernel library version address */
            uint32 dwXAPILibraryVersionAddr;            /*!< 0x016C - xapi library version address */
            uint32 dwLogoBitmapAddr;                    /*!< 0x0170 - logo bitmap address */
            uint32 dwSizeofLogoBitmap;                  /*!< 0x0174 - logo bitmap size */
        }
        image_header;

        /*! xbe image header extra bytes */
        uint08 *p_extra_bytes;

        /*! xbe certificate */
        struct _certificate
        {
            uint32  dwSize;                               /*!< 0x0000 - size of certificate */
            uint32  dwTimeDate;                           /*!< 0x0004 - timedate stamp */
            uint32  dwTitleId;                            /*!< 0x0008 - title id */
            wchar_t wszTitleName[40];                     /*!< 0x000C - title name (unicode) */
            uint32  dwAlternateTitleId[0x10];             /*!< 0x005C - alternate title ids */
            uint32  dwAllowedMedia;                       /*!< 0x009C - allowed media types */
            uint32  dwGameRegion;                         /*!< 0x00A0 - game region */
            uint32  dwGameRatings;                        /*!< 0x00A4 - game ratings */
            uint32  dwDiskNumber;                         /*!< 0x00A8 - disk number */
            uint32  dwVersion;                            /*!< 0x00AC - version */
            uint08  bzLanKey[16];                         /*!< 0x00B0 - lan key */
            uint08  bzSignatureKey[16];                   /*!< 0x00C0 - signature key */
            uint08  bzTitleAlternateSignatureKey[16][16]; /*!< 0x00D0 - alternate signature keys */
        }
        certificate;

        /*! xbe title */
        char ascii_title[40];
};

/*! size of raw xbe image header */
#define CX_CXBE_SIZEOF_IMAGE_HEADER 0x0178

#endif

