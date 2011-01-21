<?php

class Tx_Rbac_Service_ZendAccessControlService implements Tx_Rbac_AccessControlServiceInterface {
		/*
		* @var Tx_Extbase_Domain_Repository_FrontendUserRepository
		*/
		protected $feUser;

		protected $userAcl;

		/**
		* Gets a string with the resource object
		* @param string $rbacRule "@rbacRule ObjectA > new,edit,delete"
		* @return string The resource object string "ObjectA"
		**/
		protected function getRbacObjectFromRule($rbacRule) {
			$ruleArray = preg_split('/>/',$rbacRule);
			return trim($ruleArray[0]) ? strtolower(trim($ruleArray[0])): array();
		}

		/**
		* Gets an array with the actions related to a resource object
		* @param string $rbacRule "@rbacRule ObjectA > new,edit,delete"
		* @return array The actions of the resource object array('new','edit','delete')
		**/
		protected function getRbacActionsFromRule($rbacRule) {
			$actionsResult = array();
			$ruleArray = preg_split('/>/',$rbacRule);
			if (isset($ruleArray[1])) {
				$actionsArray = preg_split('/,/',$ruleArray[1]);
				foreach ($actionsArray as $actions) {
					if (trim($actions)) {
						$actionsResult[] = strtolower(trim($actions));
					}
				}
			}

			return $actionsResult;
		}
		
		/**
		* Retrurns true or false depending if a user is allowed to access the object's actions
		* @param Tx_Extbase_Domain_Repository_FrontendUserRepository $feUser FrontEnd user
		* @param mixed $rbacRule "ObjectA > new,edit,delete", could be an array of rules
		*
		**/
		public function hasAccess($feUser, $rbacRule) {
			if(!get_class($feUser) == 'Tx_Extbase_Domain_Repository_FrontendUserRepository'){
				return FALSE;
			}
			if(!is_array($rbacRule)){
				// always think that you have an array of rules
				$rbacRule = array($rbacRule);		
			}
			$this->setFeUser($feUser);
			$this->userAcl = getUserAcl();
			return $this->evalAllRbacRules($rbacRule);
		}

		protected function getUserAcl(){
			
		}
		
		protected function evalOneRbacRule($rbacRule){

		}

		protected function evalAllRbacRules($rbacRules){
			$isAllowed = TRUE;
			while ($rbacRule=array_pop($rbacRules) && $isAllowed == TRUE) {
				$isAllowed = $this->evalOneRbacRule($rbacRule);
			}
			return $isAllowed;
		}
		
		protected function setFeUser($feUser) {
			$this->feUser = $feUser;
		}

}

?>
