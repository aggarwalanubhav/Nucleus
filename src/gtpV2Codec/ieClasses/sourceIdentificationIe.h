/*
 * Copyright (c) 2020, Infosys Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 /******************************************************************************
 *
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/GtpV2StackCodeGen/tts/ietemplate.h.tt>
 ******************************************************************************/
#ifndef SOURCEIDENTIFICATIONIE_H_
#define SOURCEIDENTIFICATIONIE_H_

#include "manual/gtpV2Ie.h"



class SourceIdentificationIe: public GtpV2Ie {
public:
    SourceIdentificationIe();
    virtual ~SourceIdentificationIe();

    bool encodeSourceIdentificationIe(MsgBuffer &buffer,
                 SourceIdentificationIeData const &data);
    bool decodeSourceIdentificationIe(MsgBuffer &buffer,
                 SourceIdentificationIeData &data, Uint16 length);
    void displaySourceIdentificationIe_v(SourceIdentificationIeData const &data,
                 Debug &stream);
};

#endif /* SOURCEIDENTIFICATIONIE_H_ */
