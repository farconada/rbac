<?php
/*
* This ViewHeleper is for manage parts of fluid templates with ACLs
*
<f:rbac settings="{settings}">
	<rules>
		<rule>ObjectA > action1,action2</rule>
		<rule>ObjectB > action3</rule>
		<rule>Objectc > *</rule>
	</rules>
	<htmlIfDenied>
		<div>
			<h2>Not allowed</h2>
		</div>
	</htmlIfDenied>
	<htmlIfAllowed>
		<div>
			<h2>Ok, you are in</h2>
		</div>
	</htmlIfAllowed>
</f:rbac>
*/
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
			// initialize RBAC manager
		$accessControlService = t3lib_div::makeInstance('Tx_Rbac_Service_ZendAccessControlService');
		$this->rbacAccessControlService = $accessControlService;
		$this->rbacAccessControlService->setExtensionName($this->controllerContext->getRequest()->getControllerExtensionName());
		$this->rbacAccessControlService->setPluginSettings($settings);

			// get feUser
		$this->feUser = $GLOBALS['TSFE']->fe_user;

			// the fluid code
		$xmlString = $this->renderChildren();
		$xml = new SimpleXMLElement('<object>'.$xmlString.'</object>');

			// convert all xml rules in array
		$rbacRules = array();
		foreach ($xml->rules->rule as $rule) {
			$rbacRules[] = $rule.'';
		}

		$htmlIfDenied = $xml->htmlIfDenied->children()->asXML();
		$htmlIfAllowed = $xml->htmlIfAllowed->children()->asXML();

			// could throw exceptions
		try {
				// is there any feUser logged in?
			if ($this->feUser->user['uid'] > 0) {
					// check the ACLs
				$isAllowed = $this->rbacAccessControlService->hasAccess($this->feUser, $rbacRules);
				if (!$isAllowed) {
					return $htmlIfDenied;
				} else {
					return $htmlIfAllowed;
				}
			} else {
				// No feUser login: then Denied
				return $htmlIfDenied;
			}

		} catch (Tx_Rbac_Exception_AccessControlServiceException $exception) {
			// If there is any RbacException then only display the exception message
			// ToDo: configure by TS an option to display $htmlIfDenied and log the exception
			return $exception->getMessage();
		}
	}
}
?>
