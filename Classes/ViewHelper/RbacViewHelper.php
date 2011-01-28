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

	public function __construct() {
		parent::__construct();
		$accessControlService = t3lib_div::makeInstance('Tx_Rbac_Service_ZendAccessControlService');
		$this->rbacAccessControlService = $accessControlService;
		$this->feUser = $GLOBALS['TSFE']->fe_user;
	}

	public function render($settings) {
		$xmlString = $this->renderChildren();
		$xml = new SimpleXMLElement($xmlString);
		$rbacRules = array();
		foreach ($xml->rules->rule as $rule) {
			$rbacRules[] = $rule;
		}
		$htmlIfDenied = $xml->htmlIfDenied->children()->asXML();
		$htmlIfAllowed = $xml->htmlIfAllowed->children()->asXML();

		try {
			$this->rbacAccessControlService->setExtensionName($this->controllerContext->getRequest()->getControllerExtensionName());
			$this->rbacAccessControlService->setPluginSettings($settings);
			if ($this->fe_user->user['uid'] > 0) {
				$isAllowed = $this->rbacAccessControlService->hasAccess($this->fe_user, $rbacRules);
				if (!$isAllowed) {
					return $htmlIfDenied;
				} else {
					return $htmlIfAllowed;
				}
			}
		} catch (Tx_Rbac_Exception_AccessControlServiceException $exception) {
			return $exception->getMessage();
		}
	}
}
?>
