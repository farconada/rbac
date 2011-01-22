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
		$this->feUser = $this->getLoggedInUserObject();
		$controller = $this->request->getControllerObjectName();
		$action = $this->actionMethodName;
		$methodTags = $this->reflectionService->getMethodTagsValues($controller, $action);

		if (array_key_exists('rbacRule', $methodTags)) {

			if ($this->feUser) {

				// @rbacRule ObjectA > new,edit,delete
				$isAllowed = $this->rbacAccessControlService->hasAccess($this->feUser, $methodTags['rbacRule']);
				if(!$isAllowed) {
					$this->flashMessages->add('Access denied! You do not have the privileges for this function.');
					$this->accessDeniedAction();
				}


			} else {
				$this->flashMessages->add('Access denied - You are not logged in!');
				$this->accessDeniedAction();
			}



		}

		$this->postInitializeAction();
	}

	protected function accessDeniedAction() {
		$this->flashMessages->add('Access denied!');
	}

	/**
	* Template method to be implemented in extending controllers
	*/
	protected function preInitializeAction() {}

	/**
	* Template method to be implemented in extending controllers
	*/
	protected function postInitializeAction() {}

	/**
	* Returns a fe user domain object for a currently logged in user
	* or NULL if no user is logged in.
	*
	* @return Tx_Extbase_Domain_Model_FrontendUser  FE user object
	*/
	protected function getLoggedInUserObject() {
		$feUserUid = $GLOBALS['TSFE']->fe_user->user['uid'];
		if ($feUserUid > 0) {
		    $feUserRepository = t3lib_div::makeInstance('Tx_Extbase_Domain_Repository_FrontendUserRepository'); /* @var $feUserRepository Tx_Extbase_Domain_Repository_FrontendUserRepository */
		    $feUser = $feUserRepository->findByUid($feUserUid);
		    return $feUser;
		} else {
		    return NULL;
		}
   	}

}
?>
