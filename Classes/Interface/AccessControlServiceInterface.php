<?php
	interface Tx_Rbac_Interface_AccessControlServiceInterface {
		/**
		* Retrurns true or false depending if a user is allowed to access the object's actions
		* @param Tx_Extbase_Domain_Repository_FrontendUserRepository $feUser FrontEnd user
		* @param mixed $rbacRule "ObjectA > new,edit,delete", could be an array of rules
		*
		**/
		public function hasAccess($feUser, $rbacRule);
	}
?>
