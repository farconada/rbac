<?php
require 'Zend/Acl.php';
require 'Zend/Acl/Role.php';
require 'Zend/Acl/Resource.php';
require 'Zend/Acl/Exception.php';

class Tx_Rbac_Service_ZendAccessControlService implements Tx_Rbac_Interface_AccessControlServiceInterface {
		/*
		* @var tslib_feUserAuth
		*/
		protected $feUser;

		protected $userAcl;

		protected $extensionName;

		protected $pluginSettings;

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
			if(!is_array($rbacRule)){
				// always think that you have an array of rules
				$rbacRule = array($rbacRule);
			}
			$this->setFeUser($feUser);
			$this->userAcl = $this->getUserAcl();

			return $this->evalAllRbacRules($rbacRule);
		}

		private function getUserRolesFromTS() {
			$userTs = $this->feUser->getUserTSconf();
			if(isset($userTs['plugin.']['tx_'.$this->extensionName.'.']['settings.']['rbac.']['roles.'])){
				return Tx_Extbase_Utility_TypoScript::convertTypoScriptArrayToPlainArray($userTs['plugin.']['tx_'.$this->extensionName.'.']['settings.']['rbac.']['roles.']);
			} else {
				return array();
			}

		}

		private function getPluginRolesFromTS(){
			if(isset($this->pluginSettings['rbac']['roles'])) {
				return $this->pluginSettings['rbac']['roles'];
			} else {
				return array();
			}
		}

		protected function getUserAcl(){
			$acl = new Zend_Acl();
			$roles = Tx_Extbase_Utility_Arrays::arrayMergeRecursiveOverrule($this->getPluginRolesFromTS(), $this->getUserRolesFromTS());
			//t3lib_div::debug($roles);
			foreach ($roles as $roleName => $roleValues) {
				try {
					// create the roles
					$acl->addRole(strtolower(trim($roleName)),Tx_Extbase_Utility_Arrays::trimExplode(',', $roleValues['parentRoles'],TRUE));
					foreach($roleValues as $ruleObject => $ruleValues){
						// Common actions for all resource objects
						if (strtolower(trim($ruleObject)) == 'commonactions') {
							if (isset($ruleValues['allow'])) {
								$actions = Tx_Extbase_Utility_Arrays::trimExplode(',', $ruleValues['allow'],TRUE);
								$acl->allow(strtolower(trim($roleName)),null,$actions);
								//t3lib_div::debug('allow role: '.strtolower(trim($roleName)).' resource: '. null .' actions: '.implode(',', $actions)."\n");echo "<br />";
							}
							if (isset($ruleValues['deny'])) {
								$actions = Tx_Extbase_Utility_Arrays::trimExplode(',', $ruleValues['deny'],TRUE);
								$acl->deny(strtolower(trim($roleName)),null,$actions);
								//t3lib_div::debug('deny role: '.strtolower(trim($roleName)).' resource: '. null .' actions: '.implode(',', $actions)."\n");echo "<br />";
							}
						} else {
							if(!(strtolower(trim($ruleObject)) == 'parentroles')) {
								try {
									$acl->addResource(strtolower(trim($ruleObject)));
								} catch (Zend_Acl_Exception $exception) {
									// If Resource already exists then ignore
								}
								// actions for selected resource Objects
								$actions = Tx_Extbase_Utility_Arrays::trimExplode(',', $ruleValues['actions'],TRUE);
								if(!isset($ruleValues['allowed']) || $ruleValues['allowed']){
									$acl->allow(strtolower(trim($roleName)),strtolower(trim($ruleObject)),$actions);
									//t3lib_div::debug('allow role: '.strtolower(trim($roleName)).' resource: '. strtolower(trim($ruleObject)) .' actions: '.implode(',', $actions)."\n");echo "<br />";
								} else {
									$acl->deny(strtolower(trim($roleName)),strtolower(trim($ruleObject)),$actions);
									//t3lib_div::debug('deny role: '.strtolower(trim($roleName)).' resource: '. strtolower(trim($ruleObject)) .' actions: '.implode(',', $actions)."\n");echo "<br />";
								}
							}
						}
					}
				} catch(Zend_Acl_Role_Registry_Exception $exception) {
					throw new Tx_Rbac_Exception_AccessControlServiceException($exception->getMessage());
				}
			}

			return $acl;

		}

		public function setExtensionName($extensionName){
			$this->extensionName = strtolower($extensionName);
		}

		public function setPluginSettings($settings){
			$this->pluginSettings = $settings;
		}
		protected function evalOneRbacRule($rbacRule){
			if( !$this->isValidRuleSyntax($rbacRule)) {
				throw new Tx_Rbac_Exception_AccessControlServiceException('RBAC error: is not valid rule syntax: '. $rbacRule);
			}
			t3lib_div::debug($rbacRule);
		}

		protected function evalAllRbacRules($rbacRules){
			$isAllowed = TRUE;
			while (($rbacRule=array_pop($rbacRules)) && $isAllowed == TRUE) {
				$isAllowed = $this->evalOneRbacRule($rbacRule);
			}
			return $isAllowed;
		}

		protected function setFeUser($feUser) {
			if(!(get_class($feUser) == 'tslib_feUserAuth') || !($feUser->user['uid'] > 0)){
				throw new Tx_Rbac_Exception_AccessControlServiceException('error: is not valid FE user of type tslib_feUserAuth');
			}
			$this->feUser = $feUser;
		}

		protected function isValidRuleSyntax($rule) {
			return preg_match('/[[:alnum:]][\t\s]*>([\t\s]*[[:alnum:]*]+[\t\s]*[,]*)+$/', $rule);
		}

}

?>
