/******************************************************************************
 *
 * Caustik's Xbox Executable Library Project
 *
 * Copyright (c) 2007, Aaron "Caustik" Robinson
 * All rights reserved.
 * 
 * File := test_cx_cxbe.cpp
 * Desc := Test module for cx_cxbe.
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

#include "../main.h"

/*! test cx_cxbe */
bool test_cx_cxbe()
{
    bool success = false;

    /*! test cx_cxbe */
    {
        bool ret;

        /*! test basic initialization */
        {
            cx_cxbe cxbe;

            ret = cxbe.open(L"X:\\cx_test\\3911\\bin\\release\\cx_xdk_blank.xbe");

            if(ret != true)
            {
                rp_debug_error("cxbe.open failed!\n");
                goto cleanup;
            }

            ret = cxbe.dump_info(stdout);

            if(ret != true)
            {
                rp_debug_error("cxbe.dump_stdout failed!\n");
                goto cleanup;
            }
        }
    }

    /*! set sucess state */
    success = true;

    goto cleanup;

cleanup:

    rp_debug_trace("[ %s ] test_cx_cxbe\n", success ? "passed" : "failed");

    return success;
}

