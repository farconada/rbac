<?php

class Tx_Rbac_Service_ZendAccessControlService implements Tx_Rbac_AccessControlServiceInterface {

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

		public function hasAccess($feUser, $rbacRule) {

		}

		protected function getUserAcl($feUser){

		}
}

?>
