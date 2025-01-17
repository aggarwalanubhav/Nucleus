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
#ifndef HEADERCOMPRESSIONCONFIGURATIONIE_H_
#define HEADERCOMPRESSIONCONFIGURATIONIE_H_

#include "manual/gtpV2Ie.h"



class HeaderCompressionConfigurationIe: public GtpV2Ie {
public:
    HeaderCompressionConfigurationIe();
    virtual ~HeaderCompressionConfigurationIe();

    bool encodeHeaderCompressionConfigurationIe(MsgBuffer &buffer,
                 HeaderCompressionConfigurationIeData const &data);
    bool decodeHeaderCompressionConfigurationIe(MsgBuffer &buffer,
                 HeaderCompressionConfigurationIeData &data, Uint16 length);
    void displayHeaderCompressionConfigurationIe_v(HeaderCompressionConfigurationIeData const &data,
                 Debug &stream);
};

#endif /* HEADERCOMPRESSIONCONFIGURATIONIE_H_ */
