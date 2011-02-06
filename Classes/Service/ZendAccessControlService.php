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

		/*
		 * @var Zend_Acl
		 */
		protected $userAcl;

		/*
		 * @var string Name of the extension managed: used to retrieve the user TS
		 */
		protected $extensionName;

		/*
		 * @var array Controller Settings: to retrieve the page-TS level defined roles
		 */
		protected $pluginSettings;


		/**
		* Gets a string with the resource object
		* @param string $rbacRule "@rbacRule ObjectA > new,edit,delete"
		* @return string The resource object string "objecta" trimed and lowercased
		**/
		protected function getRbacObjectFromRule($rbacRule) {
			$ruleArray = preg_split('/>/',$rbacRule);
			return trim($ruleArray[0]) ? strtolower(trim($ruleArray[0])): array();
		}

		/**
		* Gets an array with the actions related to a resource object
		* @param string $rbacRule "@rbacRule ObjectA > new,edit,delete"
		* @return array The actions of the resource object array('new','edit','delete') trimed and lowercased
		**/
		protected function getRbacActionsFromRule($rbacRule) {
			$actionsResult = array();
			$ruleArray = preg_split('/>/',$rbacRule);
			if (isset($ruleArray[1])) {
				$actionsArray = preg_split('/,/',$ruleArray[1]);
				foreach ($actionsArray as $actions) {
					if (trim($actions)) {
						$actionsResult[] = trim($actions);
					}
				}
			}

			return $actionsResult;
		}

		/**
		* Retrurns true or false depending if a user is allowed to access the object's actions
		* The extension name should be set with setExtensionName()
		* @param Tx_Extbase_Domain_Repository_FrontendUserRepository $feUser FrontEnd user
		* @param mixed $rbacRule "ObjectA > new,edit,delete", could be an array of rules
		* @throws Tx_Rbac_Exception_AccessControlServiceException
		* @return bool
		*
		**/
		public function hasAccess($feUser, $rbacRule) {
			if(!is_array($rbacRule)){
				// always think that you have an array of rules
				$rbacRule = array($rbacRule);
			}
			$this->setFeUser($feUser);
			$this->buildUserAcl();
			return $this->evalAllRbacRules($rbacRule);
		}

		/**
		 * Get the Rbac configured roles at FE us TS
		 *
		 * @return array
		 */
		private function getUserRolesFromTS() {
			$userTs = $this->feUser->getUserTSconf();
			if(isset($userTs['plugin.']['tx_'.$this->extensionName.'.']['settings.']['rbac.']['roles.'])){
				return Tx_Extbase_Utility_TypoScript::convertTypoScriptArrayToPlainArray($userTs['plugin.']['tx_'.$this->extensionName.'.']['settings.']['rbac.']['roles.']);
			} else {
				return array();
			}

		}

		/**
		 * Get the roles defined at page TS
		 *
		 * @return array
		 */
		private function getPluginRolesFromTS(){
			if(isset($this->pluginSettings['rbac']['roles'])) {
				return $this->pluginSettings['rbac']['roles'];
			} else {
				return array();
			}
		}

		/**
		 * Get the role applied to the user
		 * Only one role per user
		 *
		 * @return string Role applied lowercased and trimed
		 */
		private function getAppliedRole() {
			$userTs = $this->feUser->getUserTSconf();
			$role = $userTs['plugin.']['tx_'.$this->extensionName.'.']['settings.']['rbac.']['appliedRole'];

			return strtolower(trim($role));
		}

		/**
		 * Builds the user ACL database and sets $this->userAcl;
		 *
		 * @throws Tx_Rbac_Exception_AccessControlServiceException
		 */
		protected function buildUserAcl(){
			$acl = new Zend_Acl();
			// All roles defined at page and user level
			$roles = Tx_Extbase_Utility_Arrays::arrayMergeRecursiveOverrule($this->getPluginRolesFromTS(), $this->getUserRolesFromTS());
			//t3lib_div:debug($roles);
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
									if($actions[0] == '*') {
										$acl->allow(strtolower(trim($roleName)),strtolower(trim($ruleObject)));
									}else {
										$acl->allow(strtolower(trim($roleName)),strtolower(trim($ruleObject)),$actions);
										//t3lib_div::debug('allow role: '.strtolower(trim($roleName)).' resource: '. strtolower(trim($ruleObject)) .' actions: '.implode(',', $actions)."\n");echo "<br />";
									}
								} else {
									if($actions[0] == '*') {
										$acl->deny(strtolower(trim($roleName)),strtolower(trim($ruleObject)));
									}else {
										$acl->deny(strtolower(trim($roleName)),strtolower(trim($ruleObject)),$actions);
										//t3lib_div::debug('deny role: '.strtolower(trim($roleName)).' resource: '. strtolower(trim($ruleObject)) .' actions: '.implode(',', $actions)."\n");echo "<br />";
									}
								}
							}
						}
					}
				} catch(Zend_Acl_Role_Registry_Exception $exception) {
					throw new Tx_Rbac_Exception_AccessControlServiceException($exception->getMessage());
				}
			}

			$this->userAcl = $acl;
		}

		/**
		 * Return the user ACL to be queried
		 *
		 * @return Zend_Acl The user ACL
		 */
		protected function getUserAcl() {
			return $this->userAcl;
		}

		/**
		 * Sets the extension name. requered to be able to retrieve the user TS
		 * without tx_
		 *
		 * @param string $extensionName
		 */
		public function setExtensionName($extensionName){
			$this->extensionName = strtolower($extensionName);
		}

		/**
		 * Controller plugins settings
		 * To be able to retrieve page defined roles
		 *
		 * @param array $settings
		 */
		public function setPluginSettings($settings){
			$this->pluginSettings = $settings;
		}

		/**
		 * Evals one rbac rule
		 * Each action in a rule is evalueted individually
		 *
		 * @param string $rbacRule // @rbacRule ObjectA > new,edit,delete
		 * @throws Tx_Rbac_Exception_AccessControlServiceException
		 * @return bool TRUE if the user is allowed for all actions
		 */
		protected function evalOneRbacRule($rbacRule){
			if( !$this->isValidRuleSyntax($rbacRule)) {
				throw new Tx_Rbac_Exception_AccessControlServiceException('RBAC error: is not valid rule syntax: '. $rbacRule);
			}

			$rbacRuleObject = $this->getRbacObjectFromRule($rbacRule);
			$rbacRuleActions = $this->getRbacActionsFromRule($rbacRule);
			$appliedRole = $this->getAppliedRole();

			// If one action in the rule is evaluated false, then return false
			$isAllowed = TRUE;
			while (($action=array_pop($rbacRuleActions)) && ($isAllowed == TRUE)) {
				try {
					if ($action == '*') {
						$isAllowed = $this->userAcl->isAllowed($appliedRole,$rbacRuleObject);
					} else {
						$isAllowed = $this->userAcl->isAllowed($appliedRole,$rbacRuleObject,$action );
					}
				} catch(Zend_Acl_Exception $exception) {
					// If the resource is not defined the return FALSE
					if (preg_match('/Resource .* not found/', $exception->getMessage()) || preg_match('/Role .* not found/', $exception->getMessage())) {
						return FALSE;
					}
					throw new Tx_Rbac_Exception_AccessControlServiceException($exception->getMessage());
				}
			}
			//t3lib_div::debug($this->userAcl);
			return $isAllowed;
		}

		/**
		 * Evals an array of Rbac rules
		 *
		 * @param array $rbacRules
		 * @return bool TRUE if the user is allowed for all rules
		 */
		protected function evalAllRbacRules($rbacRules){
			$isAllowed = TRUE;
			while (($rbacRule=array_pop($rbacRules)) && $isAllowed == TRUE) {
				$isAllowed = $this->evalOneRbacRule($rbacRule);
			}
			return $isAllowed;
		}

		/**
		 * Sets the fe user to ask for access
		 *
		 * @param tslib_feUserAuth $feUser
		 * @throws Tx_Rbac_Exception_AccessControlServiceException
		 */
		protected function setFeUser($feUser) {
			if(!(get_class($feUser) == 'tslib_feUserAuth') || !($feUser->user['uid'] > 0)){
				throw new Tx_Rbac_Exception_AccessControlServiceException('error: is not valid FE user of type tslib_feUserAuth');
			}
			$this->feUser = $feUser;
		}

		/**
		 * Tests the RbacRule Syntax
		 * rbacRule: ObjectA > new,edit,delete
		 * rbacRule: ObjectA > *
		 * @param string $rule
		 * @return bool TRUE if the syntax is OK
		 */
		protected function isValidRuleSyntax($rule) {
			return preg_match('/[[:alnum:]][\t\s]*>([\t\s]*[[:alnum:]*]+[\t\s]*[,]*)+$/', $rule);
		}

}

?>
