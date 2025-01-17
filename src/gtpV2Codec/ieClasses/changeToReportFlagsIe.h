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
#ifndef CHANGETOREPORTFLAGSIE_H_
#define CHANGETOREPORTFLAGSIE_H_

#include "manual/gtpV2Ie.h"



class ChangeToReportFlagsIe: public GtpV2Ie {
public:
    ChangeToReportFlagsIe();
    virtual ~ChangeToReportFlagsIe();

    bool encodeChangeToReportFlagsIe(MsgBuffer &buffer,
                 ChangeToReportFlagsIeData const &data);
    bool decodeChangeToReportFlagsIe(MsgBuffer &buffer,
                 ChangeToReportFlagsIeData &data, Uint16 length);
    void displayChangeToReportFlagsIe_v(ChangeToReportFlagsIeData const &data,
                 Debug &stream);
};

#endif /* CHANGETOREPORTFLAGSIE_H_ */
