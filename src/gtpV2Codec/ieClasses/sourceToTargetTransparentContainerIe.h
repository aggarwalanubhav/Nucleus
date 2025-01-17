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
#ifndef SOURCETOTARGETTRANSPARENTCONTAINERIE_H_
#define SOURCETOTARGETTRANSPARENTCONTAINERIE_H_

#include "manual/gtpV2Ie.h"



class SourceToTargetTransparentContainerIe: public GtpV2Ie {
public:
    SourceToTargetTransparentContainerIe();
    virtual ~SourceToTargetTransparentContainerIe();

    bool encodeSourceToTargetTransparentContainerIe(MsgBuffer &buffer,
                 SourceToTargetTransparentContainerIeData const &data);
    bool decodeSourceToTargetTransparentContainerIe(MsgBuffer &buffer,
                 SourceToTargetTransparentContainerIeData &data, Uint16 length);
    void displaySourceToTargetTransparentContainerIe_v(SourceToTargetTransparentContainerIeData const &data,
                 Debug &stream);
};

#endif /* SOURCETOTARGETTRANSPARENTCONTAINERIE_H_ */
