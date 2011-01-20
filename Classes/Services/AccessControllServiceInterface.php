<?php
	interface Tx_Rbac_AccessControlServiceInterface {
		/**
		* Retrurns true or false depending if a user is allowed to access the object's actions
		* @param Tx_Extbase_Domain_Repository_FrontendUserRepository $feUser FrontEnd user
		* @param string $rbacRule "ObjectA > new,edit,delete"
		*
		**/
		public function hasAccess($feUser, $rbacRule);
	}
?>
