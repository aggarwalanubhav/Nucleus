

 /*
 * Copyright 2021-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 
 /******************************************************
 * srvccHoProcedureStates.h
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/stateMachineTmpls/state.h.tt>
 ******************************************************/
 #ifndef __SRVCC_HO_PROCEDURE__
 #define __SRVCC_HO_PROCEDURE__

 #include "state.h"

 namespace mme {
	class SrvccHoStart : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static SrvccHoStart* Instance();

			/****************************************
			* SrvccHoStart
			*    Destructor
			****************************************/
			~SrvccHoStart();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* SrvccHoStart
			*    Protected constructor
			****************************************/
			SrvccHoStart();  
	};
	
	class SrvccHoWfFwdRelResp : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static SrvccHoWfFwdRelResp* Instance();

			/****************************************
			* SrvccHoWfFwdRelResp
			*    Destructor
			****************************************/
			~SrvccHoWfFwdRelResp();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* SrvccHoWfFwdRelResp
			*    Protected constructor
			****************************************/
			SrvccHoWfFwdRelResp();  
	};
	
	class SrvccHoWfPsToCsResp : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static SrvccHoWfPsToCsResp* Instance();

			/****************************************
			* SrvccHoWfPsToCsResp
			*    Destructor
			****************************************/
			~SrvccHoWfPsToCsResp();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* SrvccHoWfPsToCsResp
			*    Protected constructor
			****************************************/
			SrvccHoWfPsToCsResp();  
	};
	
	class SrvccHoWfPsToCsComp : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static SrvccHoWfPsToCsComp* Instance();

			/****************************************
			* SrvccHoWfPsToCsComp
			*    Destructor
			****************************************/
			~SrvccHoWfPsToCsComp();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* SrvccHoWfPsToCsComp
			*    Protected constructor
			****************************************/
			SrvccHoWfPsToCsComp();  
	};
	
	class SrvccHoWfDwdRelComp : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static SrvccHoWfDwdRelComp* Instance();

			/****************************************
			* SrvccHoWfDwdRelComp
			*    Destructor
			****************************************/
			~SrvccHoWfDwdRelComp();			
			
			/******************************************
			* initialize
			*  Initializes action handlers for the state
			* and next state
			******************************************/
			void initialize();

			/*****************************************
			* returns stateId
			*****************************************/
			uint16_t getStateId() const;

			/*****************************************
			* returns stateName
			*****************************************/
			const char* getStateName() const;

		protected:
			/****************************************
			* SrvccHoWfDwdRelComp
			*    Protected constructor
			****************************************/
			SrvccHoWfDwdRelComp();  
	};
	
};
#endif // __SRVCC_HO_PROCEDURE__