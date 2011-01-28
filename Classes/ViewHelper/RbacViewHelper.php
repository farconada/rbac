<?php
class Tx_Rbac_ViewHelper_RbacViewHelper extends Tx_Fluid_Core_ViewHelper_AbstractViewHelper {
	/**
	* Holds an instance of rbac access controll service
	*
	* @var Tx_Rbac_AccessControlServiceInterface
	*/
	protected $rbacAccessControlService;

	/*
	* @var tslib_feUserAuth
	*/
	protected $feUser;

	/**
	 * checks ACLs
	 *
	 * @param array $settings
	 */
	public function render($settings = '') {
		$accessControlService = t3lib_div::makeInstance('Tx_Rbac_Service_ZendAccessControlService');
		$this->rbacAccessControlService = $accessControlService;
		$this->feUser = $GLOBALS['TSFE']->fe_user;

		$xmlString = $this->renderChildren();
		$xml = new SimpleXMLElement('<object>'.$xmlString.'</object>');
		$rbacRules = array();
		foreach ($xml->rules->rule as $rule) {
			$rbacRules[] = $rule.'';
		}
		$htmlIfDenied = $xml->htmlIfDenied->children()->asXML();
		$htmlIfAllowed = $xml->htmlIfAllowed->children()->asXML();

		try {
			$this->rbacAccessControlService->setExtensionName($this->controllerContext->getRequest()->getControllerExtensionName());
			$this->rbacAccessControlService->setPluginSettings($settings);
			if ($this->feUser->user['uid'] > 0) {
				$isAllowed = $this->rbacAccessControlService->hasAccess($this->feUser, $rbacRules);
				if (!$isAllowed) {
					return $htmlIfDenied;
				} else {
					return $htmlIfAllowed;
				}
			} else {
					// No Login then Denied
				return $htmlIfDenied;
			}

		} catch (Tx_Rbac_Exception_AccessControlServiceException $exception) {
			return $exception->getMessage();
		}
	}
}
?>
