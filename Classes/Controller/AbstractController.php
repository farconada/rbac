<?php

abstract class Tx_Rbac_Controller_AbstractController extends Tx_Extbase_MVC_Controller_ActionController {
	/**
	* Holds an instance of rbac access controll service
	*
	* @var Tx_Rbac_AccessControlServiceInterface
	*/
	protected $rbacAccessControlService;

	/**
	* Constructor for all plugin controllers
	*/
	public function __construct() {
		parent::__construct();
		$this->initAccessControlService();
	}

	/**
	* Initializes Access Controll Service
	*
	*/
	protected function initAccessControlService() {
		// TODO put this into factory
		$accessControlService = t3lib_div::makeInstance('Tx_Rbac_Service_ZendAccessControlService');
		$this->rbacAccessControlService = $accessControlService;
	}

	/**
	* This action is final, as it should not be overwritten by any extended controllers
	*/
	final protected function initializeAction() {
		// TODO refactor me!!!

		$this->preInitializeAction();

		$controller = $this->request->getControllerObjectName();
		$action = $this->actionMethodName;
		$methodTags = $this->reflectionService->getMethodTagsValues($controller, $action);

		if (array_key_exists('rbacRule', $methodTags)) {
			if ($GLOBALS['TSFE']->fe_user->user['uid'] > 0) {
				// @rbacRule ObjectA > new,edit,delete
				$this->rbacAccessControlService->setExtensionName($this->request->getControllerExtensionName());
				$this->rbacAccessControlService->setPluginSettings($this->settings);
				$isAllowed = $this->rbacAccessControlService->hasAccess($GLOBALS['TSFE']->fe_user, $methodTags['rbacRule']);
				if(!$isAllowed) {
					$this->flashMessages->add('Access denied! You do not have the privileges for this function.');
					$this->buildControllerContext()->getRequest()->setControllerActionName('accessDenied');
				}


			} else {
				$this->flashMessages->add('Access denied - You are not logged in!');
				$this->buildControllerContext()->getRequest()->setControllerActionName('accessDenied');
			}
		}

		$this->postInitializeAction();
	}

	protected function accessDeniedAction() {
	}

	/**
	* Template method to be implemented in extending controllers
	*/
	protected function preInitializeAction() {}

	/**
	* Template method to be implemented in extending controllers
	*/
	protected function postInitializeAction() {}


}
?>
