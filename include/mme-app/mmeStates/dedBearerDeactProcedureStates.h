

 /*
 * Copyright 2021-present Infosys Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 
 /******************************************************
 * dedBearerDeactProcedureStates.h
 * This is an auto generated file.
 * Please do not edit this file.
 * All edits to be made through template source file
 * <TOP-DIR/scripts/SMCodeGen/templates/stateMachineTmpls/state.h.tt>
 ******************************************************/
 #ifndef __DED_BEARER_DEACT_PROCEDURE__
 #define __DED_BEARER_DEACT_PROCEDURE__

 #include "state.h"

 namespace mme {
	class DedDeactStart : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static DedDeactStart* Instance();

			/****************************************
			* DedDeactStart
			*    Destructor
			****************************************/
			~DedDeactStart();			
			
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
			* DedDeactStart
			*    Protected constructor
			****************************************/
			DedDeactStart();  
	};
	
	class DedDeactWfBearerAndSessionTearup : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static DedDeactWfBearerAndSessionTearup* Instance();

			/****************************************
			* DedDeactWfBearerAndSessionTearup
			*    Destructor
			****************************************/
			~DedDeactWfBearerAndSessionTearup();			
			
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
			* DedDeactWfBearerAndSessionTearup
			*    Protected constructor
			****************************************/
			DedDeactWfBearerAndSessionTearup();  
	};
	
	class DedDeactWfSessionTearup : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static DedDeactWfSessionTearup* Instance();

			/****************************************
			* DedDeactWfSessionTearup
			*    Destructor
			****************************************/
			~DedDeactWfSessionTearup();			
			
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
			* DedDeactWfSessionTearup
			*    Protected constructor
			****************************************/
			DedDeactWfSessionTearup();  
	};
	
	class DedDeactWfBearerTearup : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static DedDeactWfBearerTearup* Instance();

			/****************************************
			* DedDeactWfBearerTearup
			*    Destructor
			****************************************/
			~DedDeactWfBearerTearup();			
			
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
			* DedDeactWfBearerTearup
			*    Protected constructor
			****************************************/
			DedDeactWfBearerTearup();  
	};
	
	class SrvccDelDedBearer : public SM::State
	{
		public:
			/******************************************
			* Instance 
			*    Creates static instance for the state
			*******************************************/
			static SrvccDelDedBearer* Instance();

			/****************************************
			* SrvccDelDedBearer
			*    Destructor
			****************************************/
			~SrvccDelDedBearer();			
			
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
			* SrvccDelDedBearer
			*    Protected constructor
			****************************************/
			SrvccDelDedBearer();  
	};
	
};
#endif // __DED_BEARER_DEACT_PROCEDURE__
