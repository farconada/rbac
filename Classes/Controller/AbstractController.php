<?php

abstract class Tx_Rbac_Controller_AbstractController extends Tx_Extbase_MVC_Controller_ActionController {
	/**
	* Holds an instance of rbac access controll service
	*
	* @var Tx_Rbac_Domain_AccessControllService
	*/
	protected $rbacAccessControllService;

	/**
	* Constructor for all plugin controllers
	*/
	public function __construct() {
		parent::__construct();  
		$this->initAccessControllService();     
	}	

	/**
	* Initializes Access Controll Service 
	*
	*/
	protected function initAccessControllService() {
		// TODO put this into factory
		$accessControllService = new Tx_Rbac_Domain_AccessControllService();
		$this->rbacAccessControllService = $accessControllService;
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

		if (array_key_exists('rbacNeedsAccess', $methodTags)) {
		    	
			if ($this->feUser) {	
	    	
			    	$query = t3lib_div::makeInstance(Tx_Rbac_Domain_Repository_UserRepository)->createQuery();
			    	$query->getQuerySettings()->setRespectStoragePage(FALSE);
			    	$query->matching($query->equals('feUser', $this->feUser->getUid()));
			    	$rbacUser = $query->execute();
			    	
				// @rbacRule ObjectA > new,edit,delete
				$isAllowed = TRUE
				while (array_pop($methodTags['rbacRule'])=$rbacRule && $isAllowed == TRUE) {
					$rbacObject = $this->rbacAccessControllService->getRbacObjectFromRule();
					$rbacActions = $this->rbacAccessControllService->getRbacActionsFromRule();
					$isAllowed = $this->rbacAccessControllService->hasAccess($this->feUser, $rbacObject, $rbacActions);
				}

				if (count($methodTags['rbacRule'])) {
					// Some rule checked as Not Allowed
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
