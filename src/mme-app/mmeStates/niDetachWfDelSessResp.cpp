  
/*
 * Copyright 2019-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 
/**************************************
 * niDetachWfDelSessResp.cpp
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/stateMachineTmpls/state.cpp.tt>
 **************************************/

#include "smEnumTypes.h"
#include "actionTable.h"
#include "actionHandlers/actionHandlers.h"

#include "mmeStates/niDetachWfDelSessResp.h"	
#include "mmeStates/niDetachWfS1RelComp.h"

using namespace mme;
using namespace SM;

/******************************************************************************
* Constructor
******************************************************************************/
NiDetachWfDelSessResp::NiDetachWfDelSessResp():State(State_e::ni_detach_wf_del_sess_resp)
{
}

/******************************************************************************
* Destructor
******************************************************************************/
NiDetachWfDelSessResp::~NiDetachWfDelSessResp()
{
}

/******************************************************************************
* creates and returns static instance
******************************************************************************/
NiDetachWfDelSessResp* NiDetachWfDelSessResp::Instance()
{
        static NiDetachWfDelSessResp state;
        return &state;
}

/******************************************************************************
* initializes eventToActionsMap
******************************************************************************/
void NiDetachWfDelSessResp::initialize()
{
        {
                ActionTable actionTable;
                actionTable.addAction(&ActionHandlers::process_del_session_resp);
                actionTable.addAction(&ActionHandlers::send_s1_rel_cmd_to_ue);
                actionTable.setNextState(NiDetachWfS1RelComp::Instance());
                eventToActionsMap.insert(pair<Event_e, ActionTable>(Event_e::DEL_SESSION_RESP_FROM_SGW, actionTable));
        }
}