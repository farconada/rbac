<?php

class Tx_Rbac_Service_ZendAccessControlService implements Tx_Rbac_AccessControlServiceInterface {

		/**
		* Gets a string with the resource object
		* @param string $rbacRule "@rbacRule ObjectA > new,edit,delete"
		* @return string The resource object string "ObjectA"
		**/
		protected function getRbacObjectFromRule($rbacRule) {

		}

		/**
		* Gets an array with the actions related to a resource object
		* @param string $rbacRule "@rbacRule ObjectA > new,edit,delete"
		* @return array The actions of the resource object array('new','edit','delete')
		**/
		protected function getRbacActionsFromRule($rbacRule) {

		}

		public function hasAccess($feUser, $rbacRule) {

		}

		protected function getUserAcl($feUser){

		}
}

?>
