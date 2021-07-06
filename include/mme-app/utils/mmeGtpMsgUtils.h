/*
* Copyright 2020-present, Infosys Ltd.
*
* SPDX-License-Identifier: Apache-2.0
*/
#ifndef INCLUDE_MME_APP_UTILS_MMEGTPMSGUTILS_H_
#define INCLUDE_MME_APP_UTILS_MMEGTPMSGUTILS_H_



#include <stdint.h>
#include <msgType.h>
#include <smTypes.h>

namespace SM
{
	class ControlBlock;
}
namespace mme
{
	class S1HandoverProcedureContext;
	class MmeSmCreateBearerProcCtxt;
	class MmeSmDeleteBearerProcCtxt;
	class UEContext;
	class SessionContext;
	class SrvccProcedureContext;
	class MmeGtpMsgUtils
	{
	public:
		static void populateModifyBearerRequestHo(SM::ControlBlock& cb,
		        UEContext& ueCtxt,
		        SessionContext& sessCtxt,
				S1HandoverProcedureContext& procCtxt,
				struct MB_Q_msg& mbMsg);

        static bool populateCreateBearerResponse(SM::ControlBlock& cb,
                MmeSmCreateBearerProcCtxt& procCtxt, struct CB_RESP_Q_msg& cb_resp);

        static bool populateDeleteBearerResponse(SM::ControlBlock& cb,
                MmeSmDeleteBearerProcCtxt& procCtxt, struct DB_RESP_Q_msg& db_resp);

		static void populateDeleteBearerCommand(SM::ControlBlock& cb,
				UEContext& ueCtxt, SessionContext& sessionCtxt,
				SrvccProcedureContext& procCtxt,
				struct DELETE_BEARER_COMMAND_msg& db_command_msg);

		static void populatePsToCsRequest(SM::ControlBlock& cb,
				UEContext& ueCtxt,
				SrvccProcedureContext& procCtxt,
				struct PS_to_CS_REQ_msg& psToCsReq);

		static void populateForwardRelocationRequest(SM::ControlBlock& cb,
				UEContext& ueCtxt,
				SessionContext& sessionCtxt,
				SrvccProcedureContext& procCtxt,
				struct FORWARD_REL_REQ_msg& fwd_rel_req);
		
	private:
		MmeGtpMsgUtils();
		~MmeGtpMsgUtils();
	};
}

#endif /* INCLUDE_MME_APP_UTILS_MMEGTPMSGUTILS_H_ */
