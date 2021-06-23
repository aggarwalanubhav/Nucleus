

 
/*
 * Copyright 2019-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 
/**************************************
 * .cpp
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/stateMachineTmpls/stateFactory.cpp.tt>
 **************************************/

#include "mmeSmDefs.h"
#include "mmeStates/stateFactory.h"
#include "mmeStates/defaultMmeProcedureStates.h"
#include "mmeStates/attachStates.h"
#include "mmeStates/ueInitDetachStates.h"
#include "mmeStates/s1ReleaseStates.h"
#include "mmeStates/networkInitDetachStates.h"
#include "mmeStates/serviceRequestStates.h"
#include "mmeStates/tauStates.h"
#include "mmeStates/s1HandoverStates.h"
#include "mmeStates/srvccHoProcedureStates.h"
#include "mmeStates/erabModIndicationStates.h"
#include "mmeStates/createBearerProcedureStates.h"
#include "mmeStates/dedBearerActProcedureStates.h"
#include "mmeStates/deleteBearerProcedureStates.h"
#include "mmeStates/dedBearerDeactProcedureStates.h"

using namespace mme;

/**********************************************
* Constructor
***********************************************/
StateFactory::StateFactory()
{
}

/**********************************************
* Destructor
***********************************************/
StateFactory::~StateFactory()
{
}

/**********************************************
* creates and returns static instance
***********************************************/

StateFactory* StateFactory::Instance()
{
	static StateFactory instance;
	return &instance;
}

void StateFactory::initialize()
{
	AttachStart::Instance()->initialize();
	AttachState::Instance()->initialize();
	AttachWfAia::Instance()->initialize();
	AttachWfAttCmp::Instance()->initialize();
	AttachWfAuthResp::Instance()->initialize();
	AttachWfAuthRespValidate::Instance()->initialize();
	AttachWfCsResp::Instance()->initialize();
	AttachWfEsmInfoCheck::Instance()->initialize();
	AttachWfEsmInfoResp::Instance()->initialize();
	AttachWfIdentityResponse::Instance()->initialize();
	AttachWfImsiValidateAction::Instance()->initialize();
	AttachWfInitCtxtResp::Instance()->initialize();
	AttachWfInitCtxtRespAttCmp::Instance()->initialize();
	AttachWfMbResp::Instance()->initialize();
	AttachWfSecCmp::Instance()->initialize();
	AttachWfUla::Instance()->initialize();
	CreateBearerStart::Instance()->initialize();
	CreateBearerWfDedActComplete::Instance()->initialize();
	CreateBearerWfPagingComplete::Instance()->initialize();
	DedActStart::Instance()->initialize();
	DedActWfBearerAndSessionSetup::Instance()->initialize();
	DedActWfBearerSetup::Instance()->initialize();
	DedActWfSessionSetup::Instance()->initialize();
	DedDeactStart::Instance()->initialize();
	DedDeactWfBearerAndSessionTearup::Instance()->initialize();
	DedDeactWfBearerTearup::Instance()->initialize();
	DedDeactWfSessionTearup::Instance()->initialize();
	DefaultMmeState::Instance()->initialize();
	DeleteBearerStart::Instance()->initialize();
	DeleteBearerWfDeactComplete::Instance()->initialize();
	DeleteBearerWfPagingComplete::Instance()->initialize();
	DetachStart::Instance()->initialize();
	DetachWfDelSessionResp::Instance()->initialize();
	DetachWfPurgeResp::Instance()->initialize();
	DetachWfPurgeRespDelSessionResp::Instance()->initialize();
	ErabModIndStart::Instance()->initialize();
	ErabModIndWfMbResp::Instance()->initialize();
	IntraS1HoStart::Instance()->initialize();
	NiDetachStart::Instance()->initialize();
	NiDetachState::Instance()->initialize();
	NiDetachWfDelSessResp::Instance()->initialize();
	NiDetachWfDetAccptDelSessResp::Instance()->initialize();
	NiDetachWfDetachAccept::Instance()->initialize();
	NiDetachWfS1RelComp::Instance()->initialize();
	PagingStart::Instance()->initialize();
	PagingWfServiceReq::Instance()->initialize();
	S1HoWfHoNotify::Instance()->initialize();
	S1HoWfHoRequestAck::Instance()->initialize();
	S1HoWfModifyBearerResponse::Instance()->initialize();
	S1HoWfTauCheck::Instance()->initialize();
	S1HoWfTauRequest::Instance()->initialize();
	S1ReleaseStart::Instance()->initialize();
	S1ReleaseWfReleaseAccessBearerResp::Instance()->initialize();
	S1ReleaseWfSrvccResourceRelease ::Instance()->initialize();
	S1ReleaseWfUeCtxtReleaseComp::Instance()->initialize();
	ServiceRequestStart::Instance()->initialize();
	ServiceRequestState::Instance()->initialize();
	ServiceRequestWfAia::Instance()->initialize();
	ServiceRequestWfAuthRespValidate::Instance()->initialize();
	ServiceRequestWfAuthResponse::Instance()->initialize();
	ServiceRequestWfInitCtxtResp::Instance()->initialize();
	ServiceRequestWfMbResp::Instance()->initialize();
	ServiceRequestWfSecCmp::Instance()->initialize();
	SrvccDelDedBearer::Instance()->initialize();
	SrvccDeleteBearerStart::Instance()->initialize();
	SrvccDeleteBearerWfDeactComplete::Instance()->initialize();
	SrvccHoStart::Instance()->initialize();
	SrvccHoWfDwdRelComp::Instance()->initialize();
	SrvccHoWfFwdRelResp::Instance()->initialize();
	SrvccHoWfPsToCsComp::Instance()->initialize();
	SrvccHoWfPsToCsResp::Instance()->initialize();
	TauStart::Instance()->initialize();

        populateEventStringMap();
}
