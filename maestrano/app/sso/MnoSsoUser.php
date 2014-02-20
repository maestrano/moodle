<?php

/**
 * Configure App specific behavior for 
 * Maestrano SSO
 */
class MnoSsoUser extends MnoSsoBaseUser
{
  /**
   * Database connection
   * @var PDO
   */
  public $connection = null;
  
  
  /**
   * Extend constructor to inialize app specific objects
   *
   * @param OneLogin_Saml_Response $saml_response
   *   A SamlResponse object from Maestrano containing details
   *   about the user being authenticated
   */
  public function __construct(OneLogin_Saml_Response $saml_response, &$session = array(), $opts = array())
  {
    // Call Parent
    parent::__construct($saml_response,$session);
    
    // Assign new attributes
    $this->connection = $opts['db_connection'];
  }
  
  
  /**
   * Sign the user in the application. 
   * Parent method deals with putting the mno_uid, 
   * mno_session and mno_session_recheck in session.
   *
   * @return boolean whether the user was successfully set in session or not
   */
  protected function setInSession()
  {
    // First get user
    $user = get_complete_user_data('username', $this->uid, 1);
    $user->auth = 'manual';
    
    if ($user) {
        complete_user_login($user);
        
        return true;
    } else {
        return false;
    }
  }
  
  
  /**
   * Used by createLocalUserOrDenyAccess to create a local user 
   * based on the sso user.
   * If the method returns null then access is denied
   *
   * @return the ID of the user created, null otherwise
   */
  protected function createLocalUser()
  {
    $lid = null;
    
    if ($this->accessScope() == 'private') {
      // Build user hash
      $user_data = $this->buildLocalUser();
      
      // Create user and get id
      $lid = $this->connection->insert_record('user', $user_data);
      
      // Add user to admin list if user has admin role
      global $CFG;
      if ($this->isRoleAdmin()) {
        $admins = array();
        foreach(explode(',', $CFG->siteadmins) as $admin) {
            $admin = (int)$admin;
            if ($admin) {
                $admins[$admin] = $admin;
            }
        }
        $admins[$lid] = $lid;
        set_config('siteadmins', implode(',', $admins));
      }
    }
    
    return $lid;
  }
  
  /**
   * Build the local user for creation
   *
   * @return a hash of user data
   */
  protected function buildLocalUser()
  {
    // Generate password that complies with moodle
    $password = $this->generatePassword() . 'P!1';
    
    $user_data = Array(
      'username'      => $this->uid,
      'firstname'     => $this->name,
      'lastname'      => $this->surname,
      'email'         => $this->email,
      'maildisplay'   => 2,
      'mailformat'    => 1,
      'maildigest'    => 0,
      'autosubscribe' => 0,
      'trackforums'   => 0,
      'htmleditor'    => 1,
      'city'          => 'Sydney',
      'country'       => 'AU',
      'timezone'      => 99,
      'lang'          => 'en',
      'auth'          => 'manual',
      'mnethostid'    => 1,
      'confirmed'     => 1,
      'timecreated'   => time(),
      'timemodified'  => time(),
      'password'      => hash_internal_user_password($password),
      'course'        => 1,
      'suspended'     => 0,
      'preference_auth_forcepasswordchange' => 0
      
    );
    
    return $user_data;
  }
  
  /**
   * Return wether the user is an admin or not
   *
   * @return boolean value 
   */
  protected function isRoleAdmin()
  {
    $admin = false; // User
    
    if ($this->app_owner) {
      $admin = true; // Admin
    } else {
      foreach ($this->organizations as $organization) {
        if ($organization['role'] == 'Admin' || $organization['role'] == 'Super Admin') {
          $admin = true;
        } else {
          $admin = false;
        }
      }
    }
    
    return $admin;
  }
  
  /**
   * Get the ID of a local user via Maestrano UID lookup
   *
   * @return a user ID if found, null otherwise
   */
  protected function getLocalIdByUid()
  {
    $result = $this->connection->get_recordset_sql("SELECT id FROM mdl_user WHERE mno_uid = ? LIMIT 1", Array($this->uid));
    $result = $result->current();
    
    if ($result && $result->id) {
      return $result->id;
    }
    
    return null;
  }
  
  /**
   * Get the ID of a local user via email lookup
   *
   * @return a user ID if found, null otherwise
   */
  protected function getLocalIdByEmail()
  {
    $result = $this->connection->get_recordset_sql("SELECT id FROM mdl_user WHERE email = ? LIMIT 1", Array($this->email));
    $result = $result->current();
    
    if ($result && $result->id) {
      return $result->id;
    }
    
    return null;
  }
  
  /**
   * Set all 'soft' details on the user (like name, surname, email)
   * Implementing this method is optional.
   *
   * @return boolean whether the user was synced or not
   */
   protected function syncLocalDetails()
   {
     
     if($this->local_id) {
       $upd = $this->connection->update_record('user', Array(
         'id'        => $this->local_id,
         'email'     => $this->email,
         'firstname' => $this->name,
         'lastname'  => $this->surname,
         'username'  => $this->uid
       ));
       return $upd;
     }
     
     return false;
   }
  
  /**
   * Set the Maestrano UID on a local user via id lookup
   *
   * @return a user ID if found, null otherwise
   */
  protected function setLocalUid()
  {
    if($this->local_id) {
      $upd = $this->connection->update_record_raw('user', Array(
        'id'      => $this->local_id,
        'mno_uid' => $this->uid
      ));
      return $upd;
    }
    
    return false;
  }
}