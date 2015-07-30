<?php
header("Access-Control-Allow-Headers: Content-Type, x-requested-with, x-api-key, x-yspro, x-password");
if (isset($_SERVER['HTTP_ORIGIN'])) {
	header('Access-Control-Allow-Origin: '.$_SERVER['HTTP_ORIGIN']);
	header('Access-Control-Allow-Credentials: true');
} else {
	header('Access-Control-Allow-Origin: *');
}
header('Access-Control-Allow-Methods: POST, GET, PUT, DELETE, OPTIONS');
header('Access-Control-Max-Age: 1728000');
header('X-OTT-Webnode: '.@$_SERVER['SERVER_ADDR']);

if (strtolower($_SERVER['REQUEST_METHOD']) == 'options') {
	header('Content-type: application/json');
	header('Content-length: 0');
	exit();
}

class Users extends RestBase { 
	private $moviepartners = Array(
		'CYc4SMPLsa5YyKcHqqXt6zBZzYnuuO0BeNAJunti' => Array(	'partnerkey' => 'kino.yousee.tv' )
	);

	private $sharedsecrets = Array(
		'vkeXrZvghkTUfz7vYivoqcXm85sMVcdvrw8Ggxy0' => Array('key' => "kDeoJwQw3bErN2dJ\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 'type' => 'ios'),
		'Mb8Rjp8xc9tLNZ3vHszQFJSO37kfkC8szU0olU22' => Array('key' => "kDeoJwQw3bErN2dJ\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 'type' => 'ios'),
		'bvgr7vhfGYFTNRP2YVx01DLRy7Qwnx0AVfm5ktCH' => Array(
			'key' => "K5qPgA4NtBHbu8wcQwu2agNWHvVYVnM8", 
			'type' => 'android-blockbuster',
			'iv' => 'GvaKJPcE5ebQcXEE'
		),
	);

	protected $methods = Array(
		'login_get' => Array('level' => 10),
		'userexists_get' => Array('level' => 10),
		'logout_get' => Array('level' => 10),
		'user_post' => Array('level' => 10),
		'user_put' => Array('level' => 10),
		'user_get' => Array('level' => 10),
		'transactions_get' => Array('level' => 10),
		'isyouseeip_get' => Array('level' => 5),
		'generate_deviceid_get' => Array('level' => 5),
		'devices_get' => Array('level' => 5),
		'device_post' => Array('level' => 10),
		'device_delete' => Array('level' => 10),
		'favorites_get' => Array('level' => 10),
		'favorite_post' => Array('level' => 10),
		'favoritelist_post' => Array('level' => 10),
		'favoritelist_delete' => Array('level' => 10),
		'favorite_delete' => Array('level' => 10),
		'favorites_sortorder_put' => Array('level' => 10),
		'channel_order_get' => Array('level' => 10),
		'channel_order_post' => Array('level' => 10),
		'movielog_post' => Array('level' => 10),
		'movielog_get' => Array('level' => 10),
		'movielog_delete' => Array('level' => 10),
		'bookmark_get' => Array('level' => 10),
		'bookmarks_get' => Array('level' => 10),
		'bookmark_delete' => Array('level' => 10),
		'bookmark_post' => Array('level' => 10),
		'filmshelf_get' => Array('level' => 10)
	);
	
	public function login_get() {
		cacheHeaders(false);
		$this->load->Model('Vip');
		$this->load->Model('User');
		$username = $this->get('username');
		$password = $this->get('password');
		$flavour = $this->get('flavour');
		$token = $this->get('token');
		$socialnetwork = $this->get('socialnetwork');
		$newsletter = $this->get('newsletter');
		if (!$flavour) {
			$flavour = 'yousee';
		}

		if (!$password) {
			$password = $this->input->server('HTTP_X_PASSWORD');
		}
		// if token is set and socialnetwork is not
		// we assume old school token
		if ($token && !$socialnetwork) { 
			$this->load->library('encrypt');
			$decrypted = $this->encrypt->decode(base64_decode($token));
			if ($decrypted) {
				$foo = explode('||||', $decrypted);
				if (is_array($foo) && count($foo) == 2) {
					$username = $foo[0];
					$password = $foo[1];
				}
			}	
		}

		$apikey = $this->rest->key;
		$useencryption = (!empty($this->sharedsecrets[$apikey]['key']) && $this->get('enc'));

		if ($useencryption) {
			$enctype = $this->sharedsecrets[$apikey]['type'];

			if ($enctype == 'ios') {
				$password = $this->input->server('HTTP_X_PASSWORD');
				$password = (@mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->sharedsecrets[$apikey]['key'], base64_decode(($password)), MCRYPT_MODE_CBC));		
				$password = preg_replace('/[\x00-\x1F\x7F]/', '', $password);
			}
			else if ($enctype == 'android-blockbuster') {
				$password = $this->input->server('HTTP_X_PASSWORD');
				$cipher = new Crypt_AES();
				$cipher->setKey($this->sharedsecrets[$apikey]['key']);
				$cipher->setIV($this->sharedsecrets[$apikey]['iv']); 
				$password = $cipher->decrypt(base64_decode($password));
			}
		}	
				
		$presentableError = null;
		if ($flavour == 'yousee') {
			$session_id = Facades\YSPRO::login($username, $password);
			if ($session_id) {
				$domain = 'xmpp.yousee.tv';
				$userinfo = Facades\YSPRO::getUserInfo($session_id);
		
				if ($this->get('flavour') == 'yousee' && !$userinfo->customerNumber) { // only do this for new apps
					// WAT?
					// we don't want the old school users with customer numbers 
				
					$allowLogin = false;

					$allowLogin = $isVip = (
						$this->Vip->hasAccess($userinfo->userId, Vip::TVWEBLARGE) || 
						$this->Vip->hasAccess($userinfo->userId, Vip::ARCHIVE) || 
						$this->Vip->hasAccess($userinfo->userId, Vip::TVWEBSMALL) || 
						$this->Vip->hasAccess($userinfo->userId, Vip::MOVIE) || 
						$this->Vip->hasAccess($userinfo->userId, Vip::HBO) || 
						$this->Vip->hasAccess($userinfo->userId, Vip::CMORE) || 
						$this->Vip->hasAccess($userinfo->userId, Vip::YOUBIO)
					);	
						
					$cacheInstance = new \OdpCaching\Memcache(
						\OdpConfig\Config::getInstance()->getMemcacheServerpool()
					);
							
					$ysproInstance = new \OdpYspro\Yspro($cacheInstance);

					if (!$allowLogin) {
						// oh boy - we also need to check if the customer is a YouSee mobile customer
						// provisioned through YSPro
						$youseeMobile = new \OdpPermissions\YouSeeMobile(
							$cacheInstance,
							$ysproInstance,
							$userinfo
						);	
						$allowLogin = $youseeMobile->getPermission()->permission;
					}

					if (!$allowLogin) {
                    	// Play music users must be allowed to login
						$umapEngagement = $ysproInstance->getUmapEngagementForUserId($userinfo->userId);
						$allowLogin = !empty($umapEngagement['MSISDN']);
					}
					
					if (!$allowLogin) {
                    	// DkTv users must be allowed to login
						$allowLogin = with(new \OdpPermissions\DkTv($cacheInstance, $ysproInstance, $userinfo))->canLogin();					
					}

                    if (!$allowLogin) {
						return $this->returnRestError(
							1052,
							'Login does not grant access to app',
							'Du har forsøgt at logge ind med et login uden tilknyttede YouSee produkter. Benyt i stedet dit YouSee Login, som du finder på yousee.dk under "Mit YouSee".',
							400,
							false,
							true,
							$userinfo
						);
					}
				}
			
			} else {
				$presentableError = 'Du har indtastet forkert brugernavn eller adgangskode'; 
			}
		}
		else if ($flavour == 'tdc') {
			$session_id = Facades\CoreID::login($username, $password);
			if ($session_id) {
				$domain = 'xmpp.tdc.dk';
				$userinfo = Facades\CoreID::getUserInfo($session_id);
			} else {
				$tdcError = Facades\CoreID::getLastTdcError();
				if ($tdcError) {
					if ($tdcError = 1) {
						$presentableError = 'Du har indtastet forkert brugernavn eller adgangskode'; 
					}
					else if ($tdcError = 2) {
						$presentableError = 'Dit login er spærret i 12 timer, da du har forsøgt at logge på med forkert adgangskode 10 gange';
					}
					else if ($tdcError = 4) {
						$presentableError = 'Du skal skifte dit brugernavn på play.tdc.dk'; 
					}
					else {	
						$presentableError = 'Du har indtastet forkert brugernavn eller adgangskode'; 
					}
				}

			}
		}
		else if ($flavour == 'blockbuster') {
			if ($token && $socialnetwork) {
				try {
					$blockbusterFacebook = new \OdpYspro\BlockbusterFacebook;
					$facebookUserId = $blockbusterFacebook->getUserId($token);
				} catch (\OdpYspro\CannotConnectToFacebookOpenGraphException $e) {
					return $this->returnRestError(
						1042,
						'Cannot connect to Facebook API',
						null,
						400
					);
				} catch (\OdpYspro\CannotDecodeAccessTokenException $e) {
					return $this->returnRestError(
						1043,
						'Cannot decode facebook token',
						null,
						400
					);
				} catch (\OdpYspro\FacebookAccessTokenIsExpiredException $e) {
					return $this->returnRestError(
						1044,
						'Access token has expired',
						null,
						400
					);
				} catch (\OdpYspro\CannotReadEmailAddressException $e) {
					return $this->returnRestError(
						1048,
						'Cannot read email address from Facebook token',
						null,
						404
					);
				}
				$session_id = Facades\BlockBusterLogin::facebookLogin($facebookUserId, $token);
				if (!$session_id) {
					$status = \Facades\BlockBusterLogin::createFacebookLogin($token);
					if (!$status) {
						$lastError = Facades\BlockBusterLogin::getLastError();
						if ($lastError == 75) {
							return $this->returnRestError(
								1049,
								'Could not create user based on Facebook token. Email address '.$blockbusterFacebook->getUserEmail().' already in use',
								'Du skal først logge ind med '.$blockbusterFacebook->getUserEmail().' før du kan tilknytte din konto til Facebook',
								404
							);
						} else {
							return $this->returnRestError(
								1045,
								'Could not create user based on Facebook token',
								null,
								404
							);
						}
					}
					// only look at "newsletter" in GET login if we created user
					if ($newsletter !== false) {
						$this->User->setSetting($status->Data->UserID, User::SETTING_BB_PERMISSION_EMAIL, $newsletter == (int)1);
					}
					$this->addOnboardingMoviesToBlockbusterUser(
						$status->Data->UserID, 
						$status->Data->UserLogin, 
						$status->Data->EmailAddress
					);
					$session_id = Facades\BlockBusterLogin::facebookLogin($facebookUserId, $token);
				}
			} else {
				$session_id = Facades\BlockBusterLogin::login($username, $password);
			}
			if ($session_id) {
				$domain = 'xmpp.blockbuster.dk';
				$userinfo = Facades\BlockBusterLogin::getUserInfo($session_id);
			}		
		}

		// SA-1620 force all sessions to 25 minutes due to YSPro bug with session times
		//$expireHours = ($flavour == 'blockbuster') ? 1.5 : 11.5;
		$expireHours = 0.42;  // 25 minutes

		if ($session_id) {
		        // SA-1421 cache session_id -> user for greater logging capabilities
		        $this->Memcaching->set('yspro_sessionid'.$session_id,$username,86400); // cache session->user 24hours
			LogContext::add("username", $username);
			LogContext::add("yspro_session", $session_id);
		
			$isUserAtHome = isUserAtHome($flavour, getClientIp(), $userinfo);	
			$response = Array(
				'session_id' => $session_id, 
				'expiresinhours' => $expireHours,
				'xmpp' => with(new \OdpPermissions\GuestLoginToken)->get(
					true,
					(int) $userinfo->userId,
					$domain
				)	
			);
			$this->response($response);
		} else {
			if (!$presentableError) {
				$presentableError = 'Du har indtastet forkert brugernavn eller adgangskode'; 
			}

			return $this->returnRestError(
				1000,
				'Wrong username or password',
				$presentableError,
				404
			);
		}
	}

	public function userexists_get() {
		cacheHeaders(false);

		$token = $this->get('token');
		$flavour = $this->get('flavour');

		if (!$token || !$flavour) {
			return $this->returnRestError(
				1045,
				'Missing parameter (flavour or token)',
				null,
				400
			);
		}

		if ($flavour != 'blockbuster') {
			return $this->returnRestError(
				1046,
				'Not implemented for flavour',
				null,
				400
			);
		}

		try {
			$blockbusterFacebook = new \OdpYspro\BlockbusterFacebook;
			$facebookUserId = $blockbusterFacebook->getUserId($token);
		} catch (\OdpYspro\CannotConnectToFacebookOpenGraphException $e) {
			return $this->returnRestError(
				1042,
				'Cannot connect to Facebook API',
				null,
				400
			);
		} catch (\OdpYspro\CannotDecodeAccessTokenException $e) {
			return $this->returnRestError(
				1043,
				'Cannot decode facebook token',
				null,
				400
			);
		} catch (\OdpYspro\FacebookAccessTokenIsExpiredException $e) {
			return $this->returnRestError(
				1044,
				'Access token has expired',
				null,
				400
			);
		} catch (\OdpYspro\CannotReadEmailAddressException $e) {
			return $this->returnRestError(
				1048,
				'Cannot read email address from Facebook token',
				null,
				404
			);
		}

		$blockbusterLogin = Facades\BlockBusterLogin::getInstance();
		$userinfo = $blockbusterLogin->getUserInfo(null, null, null, false, $facebookUserId);

		if (!$userinfo) {
			return $this->returnRestError(
				1053,
				'User not found',
				'Brugeren blev ikke fundet',
				404
			);
		}

		// 200: found/exists
	}

	public function newpassword_get()
	{
		cacheHeaders(false);

		$username = $this->get('username');
		$method = $this->get('method');
		$flavour = $this->get('flavour');

		if (!$flavour) {
			$flavour = 'yousee';
		}	

		if (!$username) {
			return $this->returnRestError(
				1008, 
				'Mandatory parameter missing: username',
				null,
				400
			); 
		}

        if (!$method) {
            $method = 'EMAIL';
        }

		if ($flavour == 'yousee') {
			$status = Facades\YSPro::resetPassword(null, $username, $method);
		} 
		else if ($flavour == 'tdc') {
			$status = Facades\CoreID::resetPassword(null, $username, $method);
		}
		else if ($flavour == 'blockbuster') {
			$status = Facades\BlockBusterLogin::resetPassword(null, $username, $method);
		}

		if (!$status) {
			return $this->returnRestError(
				1050, 
				'Unknown user',
				'Det indtastede brugernavn kan ikke genkendes eller har intet mobilnummer tilknyttet',
				404
			); 
		}

		return $this->response(Array('status' => 'ok'), 200);
	}
	
	public function newpassword_post()
	{
		cacheHeaders(false);

		$password = $this->post('password');
		$flavour = $this->post('flavour');
		$userId = $this->post('userid');
		$expires = $this->post('expires');
		$hmac = $this->post('hmac');

		if (!$flavour) {
			$flavour = 'yousee';
		}	

		if (!$hmac || !$password || !$userId || !$expires) {
			return $this->returnRestError(
				1008,
				'Mandatory parameter missing: hmac, password, expires, userid',
				null,
				400
			);	
		}

		$authMessage = (object) Array(
			"HMAC" => $hmac,
			"MessageData" => (object) Array(
				"userid" => $userId,
				"expires" => $expires
			)
		);
		if ($flavour == 'yousee') {
			$status = Facades\YSPro::updateUserInfo(
				null, 
				null,
				$userId,
				$password,
				null,
				null,
				null,
				null,
				null,
				null,
				json_encode($authMessage)	
			);
		} 
		else if ($flavour == 'tdc') {
			$status = Facades\CoreID::updateUserInfo(
				null, 
				null,
				$userId,
				$password,
				null,
				null,
				null,
				null,
				null,
				null,
				json_encode($authMessage)	
			);
		}
		else if ($flavour == 'blockbuster') {
			$status = Facades\BlockBusterLogin::updateUserInfo(
				null, 
				null,
				$userId,
				$password,
				null,
				null,
				null,
				null,
				null,
				null,
				json_encode($authMessage)	
			);
		}

		if (!$status) {
			return $this->returnRestError(
				1051,
				'Could not set new password',
				'Der skete en fejl ved opdatering af kodeord',
				400
			);	
		}

		return $this->response(Array('status' => 'ok'), 200);
	}

	public function isvalidpassword_get()
	{
		cacheHeaders(false);

		$username = $this->get('username');
		$password = $this->get('password');
		$flavour = $this->get('flavour');

		if (!$flavour) {
			$flavour = 'yousee';
		}

		if (!$password) {
			$password = $this->input->server('HTTP_X_PASSWORD');
		}

		if (!$username || !$password) {
			return $this->returnRestError(
				1008,
				'Mandatory parameter missing: username, password',
				null,
				400
			);	
		}

		if ($flavour == 'yousee') {
			$statusCode = \Facades\YSPro::checkPasswordValidity($username, $password);
		}
		else if ($flavour == 'blockbuster') {
			$statusCode = \Facades\BlockBusterLogin::checkPasswordValidity($username, $password);
		}
		else if ($flavour == 'tdc') {
			$statusCode = \Facades\CoreID::checkPasswordValidity($username, $password);
		}
		else {
			return $this->returnRestError(
				1008,
				'Mandatory parameter missing: valid flavour',
				null,
				400
			);	
		}

		if ($statusCode !== true) {
			$errorCode = 1047;
            $errorTexts = \OdpYspro\Yspro::passwordValidityCodeToErrorTexts($statusCode);
			return $this->returnRestError(
				$errorCode,
				$errorTexts['error'],
                $errorTexts['presentableError'],
				406
			);	
		}

		$this->response(Array('status' => 'ok'), 200);
	}

	public function renewedtoken_get()
	{
		cacheHeaders(false);
		$flavour = $this->get('flavour');
		$renewalToken = $this->get('token');

		if (!$flavour) {
			$flavour = 'yousee';
		}	

		if (!$renewalToken) {
			return $this->returnRestError(
				1008,
				'Mandatory parameter missing: token',
				null,
				400
			);	
		}
	

		$guestLoginToken = with(new \OdpPermissions\GuestLoginToken)->validateRenewalToken($renewalToken);
		
		if ($guestLoginToken) {
			$this->response($guestLoginToken, 200);
		} else {
			return $this->returnRestError(
				1010,
				'Renewal token is invalid',
				null,
				410
			);	
		}
	}

	public function logintoken_get() {
		cacheHeaders(false);
		$this->load->library('encrypt');
		$username = $this->get('username');	
		$password = $this->get('password');	

		$token = $username.'||||'.$password;
		
		$this->response(Array('token' => base64_encode($this->encrypt->encode($token))), 200);
	}
	
	public function usersession_get() {
		cacheHeaders(false);
		$yspro = get_cookie('yspro');
		
		if (!$yspro) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}

		if (!Facades\YSPRO::getUserInfo($yspro)) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		$this->response(Array('session_id' => $yspro), 200);
	}

	public function logout_get() {
		cacheHeaders(false);
		
		$flavour = $this->get('flavour');
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));

		if (!$flavour) {
			$flavour = 'yousee';
		}

		if ($flavour == 'yousee') {
			$status = Facades\YSPRO::logout($yspro);
		} 
		else if ($flavour == 'tdc') {
			$status = Facades\CoreID::logout($yspro);
		}
		else if ($flavour == 'blockbuster') {
			$status = Facades\BlockBusterLogin::logout($yspro);
		}
		$this->response(Array('status' => 'ok'), 200);
	}

	public function user_post() {
		cacheHeaders(false);
		$this->load->model('YSPro');
		$this->load->model('User');
		$this->load->model('Transaction');

		$regexp = '/^([a-zA-ZæøåÆØÅ0-9_.-])+@([a-zA-ZæøåÆØÅ0-9_.-])+\.([a-zA-Z])+([a-zA-Z])+/';

		$email		= $this->post('email');
		$firstname	= $this->post('firstname');
		$lastname	= $this->post('lastname');
		$password	= $this->post('password');
		$newsletter = $this->post('newsletter');
		$socialnetwork = $this->post('socialnetwork');
		$token = $this->post('token');
		$sendactivationmail = $this->post('sendactivationmail');
		$flavour = $this->post('flavour');

		if (!$flavour) {
			$flavour = 'yousee';
		}

		if (!$socialnetwork && !$token) {
			if (!preg_match($regexp, $email)) {	
				return $this->returnRestError(
					1001, 
					'Invalid email address: '.$email,
					null,
					400
				); 
			}

            $pwdValidity = \Facades\YSPro::checkPasswordValidity($email, $password);

            if ($pwdValidity !== true) {
                $errorTexts = \OdpYspro\Yspro::passwordValidityCodeToErrorTexts($pwdValidity);
                return $this->returnRestError(
                    1004,
                    $errorTexts['error'],
                    $errorTexts['presentableError'],
                    400
                );
            }
		} else {
			if ($socialnetwork && !$token) {
				return $this->returnRestError(
					1044, 
					'Missing token',
					null,
					404
				); 
			}
			else if (!$socialnetwork && $token) {
				return $this->returnRestError(
					1045, 
					'Missing socialnetwork',
					null,
					404
				); 
			}
		}

		if ($flavour == 'blockbuster') {
			if ($socialnetwork && $token) {
				$status = \Facades\BlockBusterLogin::createFacebookLogin($token);
			} else {
				$status = \Facades\BlockBusterLogin::createLogin(
					($firstname) ?: '-',
					($lastname) ?: '-',
					$password,
					$email,
					$email
				);
			}
		} else {
			$status = $this->YSPro->createLogin($email, $password, $firstname, $lastname, $email);		
		}
	
		if ($flavour == 'blockbuster' && !$status) {
			$lastError = \Facades\BlockBusterLogin::getLastError();

            // 
            if ($token) {
                // Not sure this is nessasary
                $facebookUserId = with(new \OdpYspro\BlockbusterFacebook)->getUserId($token);
        
                // get email from facebook
			    $display_email = $blockbusterFacebook->getUserEmail();
            } else {
                // Get email from post
                $display_email = $email;
            }

            // Not able to find email from facebook when token not set
            if ($lastError == 75) {
				$userInfoForAlreadyExistingUser = \Facades\BlockBusterLogin::getUserInfo(null, null, null, false, null, $display_email);
                if ($userInfoForAlreadyExistingUser && $userInfoForAlreadyExistingUser->facebookUserId) {
                    $presentableError = 'Email adressen '.$display_email.' er allerede tilknyttet en Facebook konto. Benyt Facebook til at logge ind';
                } else {
                    $presentableError = 'Email adressen '.$display_email.' er allerede oprettet. Har du glemt dit kodeord kan du nulstille det på blockbuster.dk';
                }
                return $this->returnRestError(
                    1049,
                    // 'Could not create user based on Facebook token. Email address '.$display_email.' already in use',
                    'Could not create user. Email address '.$display_email.' already in use',
                    $presentableError,
                    404
                );
			} else {
				$error[0] = \Facades\BlockBusterLogin::getLastError();
				$errortext = '';
				return $this->returnRestError(
					1006, 
					'Error from YSPro: '.$errortext,
					null,
					400
				); 
			}	
		} 
		else if ($flavour != 'blockbuster' && !trim($status)) {
			$errortext = $this->YSPro->getLastError();
			$error = explode('|',$errortext);
			
			if ($error[0] == 75) {
				return $this->returnRestError(
					1005, 
					'Username already exists',
					null,
					400
				); 
			}
			else {
				return $this->returnRestError(
					1006, 
					'Error from YSPro: '.$errortext,
					null,
					400
				); 
			}
		}

		if ($flavour == 'blockbuster') {
			if ($newsletter !== false) {
				$this->User->setSetting($status->Data->UserID, User::SETTING_BB_PERMISSION_EMAIL, $newsletter == (int)1);
			}

			$this->addOnboardingMoviesToBlockbusterUser(
				$status->Data->UserID, 
				$status->Data->UserLogin, 
				$status->Data->EmailAddress
			);
		}

		$this->response(Array('status' => 'ok'), 200);
	}

	public function engagement_delete()
	{
		cacheHeaders(false);
		
		$flavour = $this->delete('flavour');
		$yspro = ($this->delete('yspro')) ? $this->delete('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));

		if (!$flavour) {
			$flavour = 'yousee';
		}
		
		if ($flavour == 'yousee') {
			$ysproInstance = \OdpYspro\Yspro::getInstance('yousee', \OdpCaching\Memcache::getInstance(\OdpConfig\Config::getMemcacheServerPool()));
	 	} 
		else if ($flavour == 'blockbuster') {
			$ysproInstance = \OdpYspro\Yspro::getInstance('blockbuster', \OdpCaching\Memcache::getInstance(\OdpConfig\Config::getMemcacheServerPool()));
	 	} 
		else if ($flavour == 'tdc') {
			$ysproInstance = \OdpYspro\Yspro::getInstance('tdc', \OdpCaching\Memcache::getInstance(\OdpConfig\Config::getMemcacheServerPool()));
		}

		$userinfo = $ysproInstance->getUserInfo($yspro);

        if (!$userinfo) {
            return $this->returnRestError(
                1024,
                'Invalid user session',
                null,
                400
            );
        }

		$id = $this->delete('id');

		$status = with(new \OdpPermissions\DvbSmartcard)->removeSmartcard($userinfo, $id);

		if (!$status) {
			return $this->returnRestError(
				1056,
				'Could not remove engagement',
				'Sletning fejlede',
				409,
				false,
				true,
				$userinfo
			);
		}

		return $this->response(Array('status' => 'ok'), 200);
	}

	public function engagement_post()
	{
		cacheHeaders(false);
		
		$flavour = $this->post('flavour');
		$yspro = ($this->post('yspro')) ? $this->post('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));

		if (!$flavour) {
			$flavour = 'yousee';
		}
		
		if ($flavour == 'yousee') {
			$ysproInstance = \OdpYspro\Yspro::getInstance('yousee', \OdpCaching\Memcache::getInstance(\OdpConfig\Config::getMemcacheServerPool()));
	 	} 
		else if ($flavour == 'blockbuster') {
			$ysproInstance = \OdpYspro\Yspro::getInstance('blockbuster', \OdpCaching\Memcache::getInstance(\OdpConfig\Config::getMemcacheServerPool()));
	 	} 
		else if ($flavour == 'tdc') {
			$ysproInstance = \OdpYspro\Yspro::getInstance('tdc', \OdpCaching\Memcache::getInstance(\OdpConfig\Config::getMemcacheServerPool()));
		}

		$userinfo = $ysproInstance->getUserInfo($yspro);
        
		if (!$userinfo) {
            return $this->returnRestError(
                1024,
                'Invalid user session',
                null,
                400
            );
        }
		
		$validTypes = Array('smartcard');

		$type = $this->post('type');

		if (!$type) {
			return $this->returnRestError(
				1008,
				'Mandatory parameter missing, type',
				null,
				400
			);
		}
		
		if (!in_array($type, $validTypes)) {
			return $this->returnRestError(
				1008,
				'Invalid type, valid types are '.implode(", ", $validTypes),
				null,
				400
			);
		}

		if ($type == 'smartcard') {
			$smartcard = $this->post('smartcard');
			$pincode = $this->post('pincode');
			if (!$smartcard) {
				return $this->returnRestError(
					1008,
					'Mandatory parameter missing, smartcard',
					null,
					400
				);
			}
			if (!$pincode || $pincode != with(new \OdpPermissions\DvbSmartcard)->getPincodeFromSmartcard($smartcard)) {
				return $this->returnRestError(
					1057,
					'Invalid pincode',
					'Pinkoden er ugyldig',
					400,
					false,
					true,
					$userinfo
				);
			}
		
			$status = with(new \OdpPermissions\DvbSmartcard)->setSmartcard($userinfo, $smartcard);

			if (!$status) {
				return $this->returnRestError(
					1055,
					'ApplyEngagement failed',
					'Registrering af smartcard fejlede',
					400,
					false,
					true,
					$userinfo
				);
			}
		}
		
		return $this->response(Array('status' => 'ok'), 200);
	}

    public function user_put() {
        $this->load->model('User');

        $regexp = '/^([0-9a-zA-Z]+([_.-]?[0-9a-zA-Z]+)*@[0-9a-zA-Z]+[0-9,a-z,A-Z,.,-]*(\.){1}[a-zA-Z]{2,4})+$/';

        $email = $this->put('email');
        $firstname = $this->put('firstname');
        $lastname = $this->put('lastname');
        $password = $this->put('password');
        $oldpassword = $this->put('oldpassword');
        $phone = $this->put('phone');
		$newsletter = $this->put('newsletter');
        $flavour = $this->put('flavour');

        $yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));

        if ($flavour == 'blockbuster') {
            $ysproInstance = \Facades\BlockBusterLogin::getInstance();
        } else {
            return $this->returnRestError(
                1000,
                'Not implemented for that flavour',
                null,
                400
            );
        }

        $userinfo = $ysproInstance->getUserInfo($yspro);

        if (!$userinfo) {
            return $this->returnRestError(
                1024,
                'Invalid user session',
                null,
                400
            );
        }

        if ($email && !preg_match($regexp, $email)) {
            return $this->returnRestError(
                1001,
                'Invalid email address: ' . $email,
                null,
                400
            );
        }

        if ($password) {
            if (!$oldpassword) {
                return $this->returnRestError(
                    1008,
                    'Mandatory parameter missing - missing oldpassword when password is set',
                    null,
                    400
                );
            }

            $passwordValidity = $ysproInstance->checkPasswordValidity($userinfo->userLogin, $password);
            if ($passwordValidity !== true) {
                $errorCode = 1047;
                $errorTexts = \OdpYspro\Yspro::passwordValidityCodeToErrorTexts($passwordValidity);
                return $this->returnRestError(
                    $errorCode,
                    $errorTexts['error'],
                    $errorTexts['presentableError'],
                    406
                );
            }

            if ($passwordValidity < 0) {
                return $this->returnRestError(
                    1001,
                    'Invalid password',
                    null,
                    400
                );
            }
        }

		if ($newsletter !== false) {
			$this->User->setSetting($userinfo->userId, User::SETTING_BB_PERMISSION_EMAIL, $newsletter == (int)1);
		}

		$updateResult = $ysproInstance->updateUserInfo($yspro, null, null, $password, $oldpassword, null, $firstname, $lastname, $email, $phone);

        if (!$updateResult) {
            $lastError = $ysproInstance->getLastError();
            return $this->returnRestError(
                1006,
                'Error from YSPro: ' . $lastError->Status . ":" . $lastError->Message,
                null,
                400
            );
        } else {
            // Updating yspro seems to go well. Update kasia too.
            $kundeid = $userinfo->customerNumber;

            // We might not have a customernumber.
            if ($kundeid) {
                $kasia = new \OdpKasia\Kasia();

                # This means that if you enter an empty field it won't be changed.. Same behavier when updating in yspro above.
                # Set KasiaFields
                $kf = array();
                if ($firstname) { $kf['fornavn'] = $firstname; }
                if ($lastname) { $kf['efternavn'] = $lastname; }
                if ($email) { $kf['email'] = $email; }
                if ($phone) { $kf['mobiltelefon'] = $phone; }

                $rs = $kasia->updateCustomer($kundeid, $kf);

            }

        }

        $this->response(Array('status' => 'ok'), 200);
    }

	public function keepalive_put() {
		cacheHeaders(false);
		//$this->load->model('YSPro');
		$yspro = ($this->put('yspro')) ? $this->put('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
	
		$flavour = $this->put('flavour');

		if (!$flavour) {
			$flavour = 'yousee';
		}

		if (!$yspro) {
			return $this->returnRestError(
				1008,
				'Mandatory parameter missing: yspro',
				null,
				400
			);	
		}

		// SA-1620 force all sessions to 25 minutes due to YSPro bug with session times
		//$expireHours = ($flavour == 'blockbuster') ? 1.5 : 11.5;
		$expireHours = 0.42;  // 25 minutes

		if ($flavour == 'tdc') {
			$response = Facades\CoreID::refreshUserSession($yspro);
		} else if ($flavour == 'blockbuster') {
			$response = Facades\BlockBusterLogin::refreshUserSession($yspro);
		} else {
			$response = Facades\YSPRO::refreshUserSession($yspro);
		}

		if ($response) {
			if (!headers_sent()) {
				setcookie(
					'yspro',
					$yspro,
					time()+86400,
					'/',
					'.yousee.tv'
				);	
			}
			$this->response(Array('status' => 'ok', 'expires' => date('Y-m-d H:i:s', time()+($expireHours*3600)), 'expiresinhours' => $expireHours), 200);	
		} else {
			$presentableError = null;
			if ($flavour == 'tdc') {
				$tdcError = Facades\CoreID::getLastTdcError();
				if ($tdcError) {
					if ($tdcError->code == 7) {
						$presentableError = 'Du er blevet logget ud pga. inaktivitet';
					}
					else if ($tdcError->code == 5) {
						return $this->returnRestError(
							1046,
							'Invalid user session',
							'Det tilladte antal samtidige logins er overskredet',
							400
						);	
					}
				}
			}	
			return $this->returnRestError(
				1009,
				'Session could not be refreshed',
				$presentableError,
				400
			);	
		}
	}

	public function isyouseeip_get() {
		cacheHeaders(false);
		$this->load->model('User');
		$status = $this->User->isYouSeeIp();

		$origin = ($status) ? 'yousee' : null;
		if ($this->User->isdktvip) {
			$origin = 'dktv';
		}
		else if ($this->User->isnalip) {
			$origin = 'nal';
		}
		else if ($this->User->isaarslevip) {
			$origin = 'aarslev';
		}

		$this->response( 
			Array(
				'status' => ($status) ? 1 : -1,
				'origin' => $origin
			), 
			200
		);
	}
	
	public function guestlogin_get() {
		cacheHeaders(false);
		$flavour = $this->get('flavour');

		$ipAddress = getClientIp();

		if (!$flavour) {
			$flavour = 'yousee';
		}

		$guestLoginToken = new \OdpPermissions\GuestLoginToken;

		if ($flavour == 'yousee') {
			$ipAccess = new \OdpPermissions\IpAccess(
				\OdpCaching\Memcache::getInstance(
					\OdpConfig\Config::getInstance()->getMemcacheServerpool()
				),
				null,
				\OdpYspro\Yspro::getInstance(
					'yousee',
					\OdpCaching\Memcache::getInstance(
						\OdpConfig\Config::getInstance()->getMemcacheServerpool()
					)
				)
			);

			$permission = $ipAccess->isYouSeeIp($ipAddress);

			if (!$permission->permission) {
				$this->response($guestLoginToken->get(false));
				return;
			}
		}
		else if ($flavour == 'tdc') {
			$ipAccess = new \OdpPermissions\IpAccess(
				\OdpCaching\Memcache::getInstance(
					\OdpConfig\Config::getInstance()->getMemcacheServerpool()
				),
				new \OdpSdc\Sdc
			);
			$permission = $ipAccess->isTdcHouseHoldEnabledIp($ipAddress);
			
			if (!$permission->permission) {
				$this->response($guestLoginToken->get(false));
				return;
			}
		}

		$domain = ($flavour == 'tdc') ? 'xmpp.tdc.dk' : 'xmpp.yousee.tv';

		$this->response(
			$guestLoginToken->get(
				true,
				($permission->userId) ?: $permission->customerNumber,
				$domain
			),
			200
		);	
	}

	public function movieaccess_get() {
		cacheHeaders(false);

		$this->load->Model('Transaction');
		$this->load->Model('User');
		$this->load->library('Statsd');

		$movie_id = $this->get('movie_id');
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$flavour = $this->get('flavour');
		$apiversion = $this->get('apiversion');
		$profile_id = $this->get('profile_id');
		
		if (!$flavour) {
			$flavour = 'yousee';
		}

		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro);
			$profile_id = 'COREID';
		}

		if (!$userinfo) {
			$isUserAtHome = with(isUserAtHome($flavour, getClientIp()))->permission;

			if (!$isUserAtHome) {
				return $this->returnRestError(
					1024, 
					'Invalid user session',
					null,
					400
				); 
			}
		}

		$partnerKey = ($flavour == 'blockbuster') ? 'blockbuster' : 'yousee.tv';

		if ($userinfo) {
			$personid = $userinfo->userId;
		}

		$multipleMovieIds = false;
		if (strpos($movie_id, ',') !== false) {
			$multipleMovieIds = true;
			$movie_ids = explode(",", $movie_id);
		}
		
		if ($apiversion == 2 && !$multipleMovieIds) {
			$multipleMovieIds = true;
			$movie_ids = Array($movie_id);
		}

		if ($multipleMovieIds) {
			$accesses = Array();
			foreach ($movie_ids as $movie_id) {
				$movie_id = trim($movie_id);
				$hasAccess = $this->Transaction->hasUserAccessToMovie($personid, $movie_id, $partnerKey, false, $userinfo);

				if (!$hasAccess) {
					$isUserInDenmark = $this->User->isUserInDenmark();
					$response = array(
						'movie_id' => (string) $movie_id, 
						'access' => false, 
						'isstarted' => false, 
						'expires' => (int) -1, 
						'expiresinsec' => (int) -1, 
						'unlimited' => (bool) false, 
						'geoblocked' => (bool) (!$isUserInDenmark), 
						'accessreason' => ''
					);
					$this->logrequest('GET', '', json_encode($response), 0);
					$accesses[] = $response;
				} else {
					$rentalPeriod = ($this->Transaction->rentalPeriodDays) ?: $this->config->item('rental_period_days');
					$hasAccess = date('Y-m-d H:i:s', (strtotime($hasAccess)+($rentalPeriod*86400)));
				
					if ($this->Transaction->transactionPayAction != 'EST' && $flavour == 'blockbuster' && $this->Transaction->transactionStarted) {
						// ok - movie is already started. Therefore we override the expire time with 
						// started time + default rental_period.
						$hasAccess = date(
							'Y-m-d H:i:s', 
							(strtotime($this->Transaction->transactionStarted)+$this->config->item('rental_period'))
						);	
					}

					$response = array(
						'movie_id' => (string) $movie_id, 
						'access' => true, 
						'isstarted' => ($this->Transaction->transactionStarted) ? true : false, 
						'expires' => (string) $hasAccess, 
						'expiresinsec' => (int) (strtotime($hasAccess)-time()), 
						'unlimited' => (bool) (($this->config->item('rental_period') == (strtotime($hasAccess)-time())) || ($this->Transaction->transactionPayAction == 'EST')),
						'geoblocked' => false, 
						'accessreason' => $this->Transaction->accessReason
					);
					$this->logrequest('GET', '', json_encode($response), 0);
					$accesses[] = $response;
				}
			}
			$this->response($accesses, 200);
			return;
		} else {
			$hasAccess = $this->Transaction->hasUserAccessToMovie(
				(isset($personid) ? $personid : 0), 
				$movie_id, 
				$partnerKey, 
				false, 
				($userinfo ?: null)
			);

			if (!$hasAccess) {
				$isUserInDenmark = $this->User->isUserInDenmark();
				$response = array(
					'movie_id' => (string) $movie_id, 
					'access' => false, 
					'isstarted' => false, 
					'expires' => (int) -1, 
					'expiresinsec' => (int) -1, 
					'unlimited' => (bool) false, 
					'geoblocked' => (bool) (!$isUserInDenmark), 
					'accessreason' => ''
				);
				$this->logrequest('GET', '', json_encode($response), 0);
				$this->response($response, 200);
				return;
			} else {
				$rentalPeriod = ($this->Transaction->rentalPeriodDays) ?: $this->config->item('rental_period_days');
				$hasAccess = date('Y-m-d H:i:s', (strtotime($hasAccess)+($rentalPeriod*86400)));
				if ($this->Transaction->transactionPayAction != 'EST' && $flavour == 'blockbuster' && $this->Transaction->transactionStarted) {
					// ok - movie is already started. Therefore we override the expire time with 
					// started time + default rental_period.
					$hasAccess = date(
						'Y-m-d H:i:s', 
						(strtotime($this->Transaction->transactionStarted)+$this->config->item('rental_period'))
					);	
				}

				$response = array(
					'movie_id' => (string) $movie_id, 
					'access' => true, 
					'isstarted' => ($this->Transaction->transactionStarted) ? true : false, 
					'expires' => (string) $hasAccess, 
					'expiresinsec' => (int) (strtotime($hasAccess)-time()),
					'unlimited' => (bool) (($this->config->item('rental_period') == (strtotime($hasAccess)-time())) || ($this->Transaction->transactionPayAction == 'EST')),
					'geoblocked' => false, 
					'accessreason' => $this->Transaction->accessReason
				);
				$this->logrequest('GET', '', json_encode($response), 0);
				$this->response($response, 200);
				return;
			}
		}
	} 

	public function devices_get() {
		cacheHeaders(false);
		$this->load->model('User');

		$custno = $this->get('customerno');
		$udid	= $this->get('udid');

		if ($udid) {
			if ($row = $this->User->isDeviceAssigned($udid)) {
				$custno = $row->customerno;		
			}		
		}

		if (!$custno) { 
			$ip = $this->input->ip_address();
		
			if (!$this->User->isYouSeeIp($ip)) {
				return $this->returnRestError(
					1015, 
					'Requesting ip is not a YouSee Bredbaand address',
					null,
					400
				); 
			}
			
			$custno = $this->User->getCustomerNoFromIp($ip);
			
			if (!$custno && $this->User->isonfone) {
				$custno = $_SERVER[$this->config->item('msisdn_header')]; 
			}


			if (!$custno) {
				return $this->returnRestError(
					1016, 
					'Could not resolve customerno.',
					null,
					400
				); 
			}
		}

		$devices = Array();

		$registredDevices = $this->User->getDevices(false, $custno);

		foreach ($registredDevices as $device) {
			$devices[] = Array(	'name' => (string) $device->name, 'udid' => (string) $device->udid, 'expires' => (string) $device->expires);
		}

		$this->response(Array('devices' => $devices, 'device_limit' => (int) $this->config->item('device-limit'), 'retention_period' => (int) $this->config->item('device-lifetime')), 200);
	}

	public function device_post() {
		cacheHeaders(false);
		$this->load->model('User');

		$udid = $this->post('udid');
		$name = $this->post('name');
		$ip = $this->input->ip_address();
		
		if (!$udid || !$name) {
			return $this->returnRestError(
				1011, 
				'Mandatory parameters missing: udid, name',
				null,
				400
			); 
		}

		if (!$this->User->isYouSeeIp($ip)) {
			return $this->returnRestError(
				1013, 
				'Requesting ip is not a YouSee Bredbaand address',
				null,
				400
			); 
		}

		if ($this->User->isonfone) {
			$custno = $_SERVER[$this->config->item('msisdn_header')]; 
			$msisdn = $_SERVER[$this->config->item('msisdn_header')];
		} else {
			$custno = $this->User->getCustomerNoFromIp($ip);
			$msisdn = false;
		}

		if (!$custno) {
			$this->response(Array('errorcode' => 1012, 'error' => 'Could not resolve customerno.'), 400);
			return;	
		}

		if ($devicedata = $this->User->isDeviceAssigned($udid)) {
			if ($custno != $devicedata->customerno) {
				$status = $this->User->removeDevice($udid, false, $devicedata->customerno);
			} else {
				// hvis enheden allerede findes paa den kunde der requester, saa fornyer vi bare
				$status = $this->User->renewDevice($udid, $name, $ip, $devicedata->customerno);
				if (!$status) {
					return $this->returnRestError(
						1014, 
						'System error',
						null,
						500
					); 
				}

				$this->response(Array('status' => 'ok'), 200);
				return;
			}
		}

		$currentdevices = $this->User->getDevices($ip, $msisdn);

		if (count($currentdevices) >= $this->config->item('device-limit')) {
			return $this->returnRestError(
				1017, 
				'Device limit reached',
				null,
				400
			); 
		}

		$status = $this->User->addDevice($name, $udid, $ip, $msisdn);
			
		if (!$status) {
			return $this->returnRestError(
				1014, 
				'System error',
				null,
				500
			); 
		}

		$this->response(Array('status' => 'ok'), 200);
	}
	
	public function device_delete() {
		cacheHeaders(false);
		
		$this->load->model('User');

		$udid = $this->get('udid');
		$ip = $this->input->ip_address();
		
		if (!$udid) {
			return $this->returnRestError(
				1019, 
				'Mandatory parameters missing: udid',
				null,
				400
			); 
		}

		if (!$this->User->isYouSeeIp($ip)) {
			return $this->returnRestError(
				1020, 
				'Requesting ip is not a YouSee Bredbaand address',
				null,
				400
			); 
		}

		if ($this->User->isonfone) {
			$custno = $_SERVER[$this->config->item('msisdn_header')]; 
		} else { 
			$custno = $this->User->getCustomerNoFromIp($ip);
		}

		if (!$custno) {
			return $this->returnRestError(
				1021, 
				'Could not resolve customerno.',
				null,
				400
			); 
		}

		$status = $this->User->removeDevice($udid, false, $custno);
			
		if (!$status) {
			return $this->returnRestError(
				1022, 
				'Could not delete device.',
				null,
				400
			); 
		}

		$this->response(Array('status' => 'ok'), 200);
	}

	public function generate_deviceid_get() {
		cacheHeaders(false);
		$this->response(Array('device_id' => (string) uniqid().mt_rand(1000,9999).uniqid()), 200);
	}


	public function favorites_get() {
		if (!empty($_REQUEST['DEBUG']) && $_REQUEST['DEBUG'] == '97') {
			$this->output->enable_profiler(TRUE);	
		}
		cacheHeaders(false);
		$this->load->model('YSPro');
		$this->load->model('Userlists');
		$this->load->model('Movies');
		$this->load->model('MoviePackages');
		$this->load->model('Tvseries');
		$this->load->model('Listings');
		$type = $this->get('type');
		$flavour = $this->get('flavour');
		$profile_id = $this->get('profile_id');
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		
		if (!$flavour) {
			$flavour = 'yousee';
		}

		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro);
			$profile_id = 'COREID';
		}

		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}

		$personid = $userinfo->userId;

		$validtypes = Array('channels','movies','moviepackages','tvseries', 'programs', 'programseries');

		if (!in_array($type, $validtypes)) {
			return $this->returnRestError(
				1025, 
				'Invalid type. Valid types: '.implode(", ", $validtypes),
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}
		
		$parsedLists = Array();

		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid, $flavour);	
		}

		$lists = $this->Userlists->getLists($personid, $type, $profile_id, $flavour);
		
		
		if (!count($lists)) {
			$this->Userlists->createList($personid, $type, 'Favoritter', 0, 0, $profile_id);	
			$lists = $this->Userlists->getLists($personid, $type, $profile_id, $flavour);
		}
		
		foreach ($lists as $list) {
			$items = Array();
			$rawitems = $this->Userlists->getItemsInList($list['id'], ($type == 'channels') ? false : true);
			if ($type == 'channels') {
				$channelinfo = $this->config->item('extrachannelinfo');
				foreach ($rawitems as $rawitem) {
					$items[] = Array('id' => (string) $rawitem['track_id'], 'name' => (string) $channelinfo[$rawitem['track_id']]['nicename']); 
				}
			}	
			else if ($type == 'movies') {
				$items = Array();				
				foreach ($rawitems as $item) {
					$items[] = $item['track_id'];	
				}
				if (!count($items)) { 
					$movies = Array();
				} else {	
					$movies = $this->Movies->getMovies(
						false, 
						false, 
						false, 
						$items, 
						'FIELD(id, \''.implode("','", $items).'\')', 
						false, 
						0, 
						4000, 
						false, 
						false, 
						false, 
						true, 
						3, 
						false, 
						false, 
						false, 
						false, 
						false, 
						$this->getTechnology(),
						false,
						false,
						false,
						false,
						false,
						false,
						($flavour == 'blockbuster')
					);
				}

				$items = Array();
				foreach ($movies as $movie) {
					$items[] = Array('id' => (string) $movie['movie_id'], 'name' => (string) $movie['movie_title']); 
				}
			}
			else if ($type == 'moviepackages') {
				$items = Array();				
				
				foreach ($rawitems as $item) {
					$moviepackage = $this->MoviePackages->get($item['track_id']);
					if (!$moviepackage) { continue; }
					$items[] = Array('id' => (string) $item['track_id'], 'name' => (string) $moviepackage['name']); 
				}
			}
			else if ($type == 'tvseries') {
				$items = Array();				
				foreach ($rawitems as $item) {
					if (!$tvshow = $this->Tvseries->getNameFromUrlId($item['track_id'])) { continue; }
					$items[$item['track_id']] = Array('id' => (string) $item['track_id'], 'name' => (string) $tvshow['name']); 
				}
			}
			else if ($type == 'programs') {
				$items = Array();				
				
				foreach ($rawitems as $item) {
					$program = $this->Listings->get($item['track_id']);
					if (!$program) { continue; }
					$items[] = Array('id' => (string) $item['track_id'], 'name' => (string) $program['title']); 
				}
			}
			else if ($type == 'programseries') {
				$items = Array();				
			
				foreach ($rawitems as $item) {
					$series = $this->Listings->getSingleProgramSeries($item['track_id']);
					if (!$series) { continue; }
					$items[] = Array('id' => (string) $item['track_id'], 'name' => (string) $series->title); 
				}
			}

			$parsedLists[] = Array('id' => (int) $list['id'], 'name' => (string) $list['name'], 'type' => (string) $list['type'], 'total' => count($items), 'items' => array_values($items));
		}

		$this->response(Array('lists' => $parsedLists, 'total' => count($parsedLists)), 200);
	}

	public function favoritelist_post() {
		cacheHeaders(false);
		$this->load->model('YSPro');
		$this->load->model('Userlists');
		
		$yspro = ($this->post('yspro')) ? $this->post('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$userinfo = $this->YSPro->getUserInfo($yspro);
		if (!$userinfo) {
			$this->logrequest('POST', json_encode($_REQUEST), '', 1024);
			$this->response(Array('errorcode' => 1024, 'error' => 'Invalid user session'), 400);
			return;	
		}
		
		$userinfo = explode("|", $userinfo);
		$personid = $userinfo[0];
	
		$type = $this->post('type');
		$name = $this->post('name');
		
		if (!$name || !$type) {
			$this->response(Array('errorcode' => 1026, 'error' => 'Mandatory parameters missing: type, name'), 400);
			return;
		}	
		
		$validtypes = Array('tracks','channels','albums','movies','tvseries','programs', 'programseries');
		if (!in_array($type, $validtypes)) {
			$this->response(Array('errorcode' => 1033, 'error' => 'Invalid type. Valid types: '.implode(", ", $validtypes)), 400);
			return;	
		}

		if ($list_id = $this->Userlists->createList($personid, $type, $name)) {
			$this->response(Array('status' => 'ok', 'list_id' => $list_id), 200);
		} else {
			$this->response(Array('errorcode' => 1038, 'error' => 'System error, could not create list'), 500);
		}
	}

	public function favoritelist_delete() {
		cacheHeaders(false);
		$this->load->model('YSPro');
		$this->load->model('Userlists');
	
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$userinfo = $this->YSPro->getUserInfo($yspro);
		if (!$userinfo) {
			$this->logrequest('DELETE', json_encode($_REQUEST), '', 1024);
			$this->response(Array('errorcode' => 1024, 'error' => 'Invalid user session'), 400);
			return;	
		}
		
		$userinfo = explode("|", $userinfo);
		$personid = $userinfo[0];
	
		$list_id = $this->get('list_id');
		$type = $this->get('type');
		
		if (!$list_id || !$type) {
			$this->response(Array('errorcode' => 1026, 'error' => 'Mandatory parameters missing: list_id, type'), 400);
			return;
		}	
		
		$validtypes = Array('tracks','channels','albums','movies','tvseries','programs', 'programseries');
		if (!in_array($type, $validtypes)) {
			$this->response(Array('errorcode' => 1033, 'error' => 'Invalid type. Valid types: '.implode(", ", $validtypes)), 400);
			return;	
		}

		if (!$this->Userlists->getList($list_id, $personid, $type)) {
			$this->response(Array('errorcode' => 1028, 'error' => 'Invalid list. Wrong type or list does not belong to user'), 400);
			return false;
		}

		$status = $this->Userlists->deleteList($personid, $type, $list_id);
	
		if ($status) {
			$this->logrequest('DELETE', json_encode($_REQUEST), json_encode(Array('status' => 'ok')), 0);
			$this->response(Array('status' => 'ok'), 200);	
		} else {
			$this->logrequest('DELETE', json_encode($_REQUEST), '', 1039);
			$this->response(Array('errorcode' => 1039, 'error' => 'System error, could no delete list'), 500);
		}
	}

	public function favorite_post() {
		cacheHeaders(false);
		$this->load->model('YSPro');
		$this->load->model('Userlists');
	
		$yspro = ($this->post('yspro')) ? $this->post('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
	
		$list_id = $this->post('list_id');
		$item_id = $this->post('item_id');
		$profile_id = $this->post('profile_id');
		$type = $this->post('type');
		$flavour = $this->post('flavour');

		if (!$flavour) {
			$flavour = 'yousee';
		}

		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro);
			$profile_id = 'COREID';
		}
		
		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}

		$personid = $userinfo->userId;

		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid, $flavour);	
		}

		if (!$list_id) {
			$lists = $this->Userlists->getLists($personid, $type, $profile_id, $flavour);
			if (count($lists) === 1) {
				$list_id = $lists[0]['id'];
			}
			if (count($lists) === 0) {
				$this->Userlists->createList($personid, $type, 'Favoritter', 0, 0, $profile_id);	
				$lists = $this->Userlists->getLists($personid, $type, $profile_id, $flavour);
				$list_id = $lists[0]['id'];
			}
		}

		if (!$list_id || !$item_id || !$type) {
			return $this->returnRestError(
				1026, 
				'Mandatory parameters missing: list_id, item_id, type',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}	

		if (!$this->Userlists->getList($list_id, $personid, $type, false, $profile_id, $flavour)) {
			return $this->returnRestError(
				1028, 
				'Invalid list. Wrong type or list does not belong to user',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}

		$status = $this->Userlists->addItem($list_id, $item_id);
	
		if ($status) {
			// fire blockbuster trigger
			if (($flavour == 'blockbuster' || $flavour == 'yousee') && $type == 'movies') {
				$movieData = Facades\VodRepo::getFromIds(
					Array($item_id),
					'*',
					null,
					null,
					null,
					($flavour == 'blockbuster'),
					($flavour == 'blockbuster')
				);
				$movieData = current($movieData);
				$movieData->genres = Facades\VodRepo::getGenresForMovie($item_id);
				$movieDto = new \OdpVodMeta\Dto\Movie(
					$movieData,
					\OdpConfig\Config::getInstance(),
					new \OdpPopularity\Vod(Facades\VodRepo::getInstance()),
					Facades\VodRepo::getInstance()
				);	
		
				if ($flavour == 'blockbuster') {
		        	with(new OdpXmpp\Helpers\BlockbusterTriggers)->trigger(
       		    		$personid,
            			'favorite',
						$movieDto        
					);
				} 
				else if ($flavour == 'yousee') {
		        	with(new OdpXmpp\Helpers\YouSeeTriggers)->trigger(
       		    		$personid,
            			'favorite',
						$movieDto        
					);
				}
			}
			
			$this->response(Array('status' => 'ok'), 200);	
		} else {
			return $this->returnRestError(
				1027, 
				'System error',
				null,
				500,
				false,
				true,
				$userinfo
			); 
		}
	}

	public function favorite_delete() {
		cacheHeaders(false);
		ini_set('display_errors', 'on');
		error_reporting(E_ALL);
		$this->load->model('YSPro');
		$this->load->model('Userlists');
	
		$yspro = ($this->delete('yspro')) ? $this->delete('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		if (!$yspro) {
			$yspro = $this->get('yspro');
		}

		$list_id	= ($this->get('list_id')) ? $this->get('list_id') : $this->delete('list_id');
		$item_id	= ($this->get('item_id')) ? $this->get('item_id') : $this->delete('item_id');
		$type		= ($this->get('type')) ? $this->get('type') : $this->delete('type');
		$profile_id	= ($this->get('profile_id')) ? $this->get('profile_id') : $this->delete('profile_id');
		$flavour	= ($this->get('flavour')) ? $this->get('flavour') : $this->delete('flavour');
	
		if (!$flavour) {
			$flavour = 'yousee';
		}

		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro);
			$profile_id = 'COREID';
		}

		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		$personid = $userinfo->userId;

		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid, $flavour);	
		}
		
		if (!$list_id) {
			$lists = $this->Userlists->getLists($personid, $type, $profile_id, $flavour);
			if (count($lists) === 1) {
				$list_id = $lists[0]['id'];
			}
		}

		if (!$list_id || !$item_id || !$type) {
			return $this->returnRestError(
				1026, 
				'Mandatory parameters missing: list_id, item_id, type',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}	
		
		if (!$this->Userlists->getList($list_id, $personid, $type, false, $profile_id, $flavour)) {
			return $this->returnRestError(
				1028, 
				'Invalid list. Wrong type or list does not belong to user',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}

		$status = $this->Userlists->removeItem(false, $list_id, $item_id);
		
		if ($status) {
			if (($flavour == 'blockbuster' || $flavour == 'yousee') && $type == 'movies') {
				$movieData = Facades\VodRepo::getFromIds(
					Array($item_id),
					'*',
					null,
					null,
					null,
					($flavour == 'blockbuster'),
					($flavour == 'blockbuster')
				);
				$movieData = current($movieData);
				$movieData->genres = Facades\VodRepo::getGenresForMovie($item_id);
				$movieDto = new \OdpVodMeta\Dto\Movie(
					$movieData,
					\OdpConfig\Config::getInstance(),
					new \OdpPopularity\Vod(Facades\VodRepo::getInstance()),
					Facades\VodRepo::getInstance()
				);	
		
		        if ($flavour == 'blockbuster') {
					with(new OdpXmpp\Helpers\BlockbusterTriggers)->trigger(
       		    		$personid,
            			'unfavorite',
						$movieDto
					);
				} 
				else if ($flavour == 'yousee') {
					with(new OdpXmpp\Helpers\YouSeeTriggers)->trigger(
       		    		$personid,
            			'unfavorite',
						$movieDto
					);
				}
			}
			$this->response(Array('status' => 'ok'), 200);	
		} else {
			return $this->returnRestError(
				1027, 
				'System error',
				null,
				500,
				false,
				true,
				$userinfo
			); 
		}
	}

	public function favorites_sortorder_put() {
		cacheHeaders(false);
		$this->load->model('YSPro');
		$this->load->model('Userlists');
	
		$yspro = ($this->put('yspro')) ? $this->put('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$list_id = $this->put('list_id');
		$items = $this->put('items');
		$type = $this->put('type');
		$profile_id = $this->put('profile_id');
		$flavour	= $this->put('flavour');
	
		if (!$flavour) {
			$flavour = 'yousee';
		}

		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro);
			$profile_id = 'COREID';
		}

		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
	
		$personid = $userinfo->userId;

		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid, $flavour);	
		}
		
		if (!$list_id) {
			$lists = $this->Userlists->getLists($personid, $type, $profile_id, $flavour);
			if (count($lists) === 1) {
				$list_id = $lists[0]['id'];
			}
		}
		
		if (!$list_id || !$items || !$type) {
			return $this->returnRestError(
				1026, 
				'Mandatory parameters missing: list_id, items, type',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}	

		if (!$this->Userlists->getList($list_id, $personid, $type, false, $profile_id, $flavour)) {
			return $this->returnRestError(
				1028, 
				'Invalid list. Wrong type or list does not belong to user',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}

		if (strpos($items, ",") === false) {
			return $this->returnRestError(
				1030, 
				'Items should be a commasep. list',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}

		$status = $this->Userlists->saveSortOrderItems($personid, $list_id, $items, $type, true, $profile_id);
	
		if ($status) {
			$this->response(Array('status' => 'ok'), 200);	
		} else {
			return $this->returnRestError(
				1031, 
				'System error',
				null,
				500,
				false,
				true,
				$userinfo
			); 
		}
	}

	public function bookmark_post() {
		cacheHeaders(false);
		$this->load->model('User');
		$this->load->model('YSPro');
	
		$yspro = ($this->post('yspro')) ? $this->post('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
	
		$id = $this->post('id');
		$type = $this->post('type');
		$seconds = (int) $this->post('seconds');
		$profile_id = $this->post('profile_id');
		$flavour = $this->post('flavour');

		if (!$flavour) {
			$flavour = 'yousee';
		}

		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro);
			$profile_id = 'COREID';
		}
		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		$personid = $userinfo->userId;

		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid, $flavour);	
		}

		$validtypes = Array('movie','archive');
		if (!in_array($type, $validtypes)) {
			return $this->returnRestError(
				1033, 
				'Invalid type. Valid types: '.implode(", ", $validtypes),
				null,
				400
			); 
		}


		if (!$id || !$type || !isset($seconds)) {
			return $this->returnRestError(
				1032, 
				'Mandatory parameters missing: id, seconds, type',
				null,
				400
			); 
		}	

		if ($flavour == 'tdc' && $type == 'movie') {
			$cookies = Facades\CoreID::getCookies($yspro);
			$sdc = new \OdpSdc\Sdc($cookies->ssoSessionDataValue, $cookies->ssoUserDataValue);
			$status = $sdc->setBookmark($id, $seconds);
			
			if (!$status) { // SDC fails periodically. We just retry it. "YIUOA-3013"
				$status = $sdc->setBookmark($id, $seconds);
			}
			
			$cacheKey = 'tdc-vod-bookmarks-'.$userinfo->userId;
			$currentBookmarksInMemcache = $this->Memcaching->get($cacheKey);
			if (empty($currentBookmarksInMemcache) || !is_array($currentBookmarksInMemcache)) {
				$currentBookmarksInMemcache = Array();
			}
			$currentBookmarksInMemcache[$id] = time(); 
			$this->Memcaching->set($cacheKey, $currentBookmarksInMemcache, 0);

			// lets start saving bookmarks locally for easy transition
			$status = $this->User->registerViewProgress($personid, $id, $type, $seconds, $profile_id, $flavour);
		} else {
			$status = $this->User->registerViewProgress($personid, $id, $type, $seconds, $profile_id, $flavour);
		
			// if bookmark is past 5 minutes - we register the movie as started and sets the expiry to 2 days
			if ($flavour == 'blockbuster' && $seconds >= 300 && $type == 'movie') {
				$this->Transaction->registerMovieAsStarted($personid, $id, 'blockbuster');
			}
		}

		if ($status) {
			return $this->response(Array('status' => 'ok'), 200);	
		} else {
			return $this->returnRestError(
				1031, 
				'System error',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}
	}
	
	public function bookmark_get() {
		cacheHeaders(false);
		$this->load->model('User');
		$this->load->model('YSPro');
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
	
		$id			= $this->get('id');
		$type		= $this->get('type');
		$profile_id = $this->get('profile_id');
		$flavour 	= $this->get('flavour');

		if (!$flavour) {
			$flavour = 'yousee';
		}
		
		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro);
			$profile_id = 'COREID';
		}
		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		$personid = $userinfo->userId;
	
		
		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid, $flavour);	
		}

		$validtypes = Array('movie','archive');
		if (!in_array($type, $validtypes)) {
			return $this->returnRestError(
				1033, 
				'Invalid type. Valid types: '.implode(", ", $validtypes),
				null,
				400
			); 
		}


		if (!$id || !$type) {
			return $this->returnRestError(
				1034, 
				'Mandatory parameters missing: id, type',
				null,
				400
			); 
		}	

		if ($flavour == 'tdc' && $type == 'movie') {
			$cookies = Facades\CoreID::getCookies($yspro);
			$sdc = new \OdpSdc\Sdc($cookies->ssoSessionDataValue, $cookies->ssoUserDataValue);
			$bookmark = $sdc->getBookmark($id);
			if ($bookmark) {
				$bookmark = (object) Array(
					'type' => 'movie',
					'content' => $id,
					'markseconds' => $bookmark->seconds,
					'create_time' => date('Y-m-d H:i:s'),
					'percentage' => 50
				);	
			}
		} else {
			$bookmark = $this->User->getViewProgress($personid, $id, $type, true, $profile_id, $flavour);
		}

		if (!$bookmark) {
			$this->response(Array('seconds' => (int) 0), 200);
		} else {
			$this->response(Array('type' => (string) $bookmark->type, 'id' => (string) $bookmark->content, 'seconds' => (int) $bookmark->markseconds, 'timestamp' => (string) $bookmark->create_time, 'percentage' => (int) $bookmark->percentage), 200);
		}
	}
	
	public function bookmark_delete() {
		cacheHeaders(false);
		$this->load->model('User');
		$this->load->model('YSPro');
		
		$yspro = ($this->delete('yspro')) ? $this->delete('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		if (!$yspro) {
			$yspro = $this->get('yspro');
		}

		$id			= ($this->get('id')) ? $this->get('id') : $this->delete('id');
		$type		= ($this->get('type')) ? $this->get('type') : $this->delete('type');
		$profile_id	= ($this->get('profile_id')) ? $this->get('profile_id') : $this->delete('profile_id');
		$flavour	= ($this->get('flavour')) ? $this->get('flavour') : $this->delete('flavour');

		if (!$flavour) {
			$flavour = 'yousee';
		}
	
		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro);
			$profile_id = 'COREID';
		}

		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		$personid = $userinfo->userId;
		
		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid, $flavour);	
		}

		$validtypes = Array('movie', 'archive');
		if (!in_array($type, $validtypes)) {
			return $this->returnRestError(
				1033, 
				'Invalid type. Valid types: '.implode(", ", $validtypes),
				null,
				400
			); 
		}

		if (!$id || !$type) {
			return $this->returnRestError(
				1034, 
				'Mandatory parameters missing: id, type',
				null,
				400
			); 
		}	

		if ($flavour == 'tdc' && $type == 'movie') {
			$cookies = Facades\CoreID::getCookies($yspro);
			$sdc = new \OdpSdc\Sdc($cookies->ssoSessionDataValue, $cookies->ssoUserDataValue);
			$sdc->deleteBookmark($id);
		} else {
			$this->User->removeViewProgress($personid, $id, $type, $profile_id, $flavour);
		}
	
		$this->response(Array('status' => 'ok'), 200);
	}
	
	public function bookmarks_get() {
		cacheHeaders(false);
		$this->load->model('User');
		$this->load->model('Movies');
		$this->load->model('YSPro');
	
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
	
		$type		= $this->get('type');
		$profile_id = $this->get('profile_id');
		$flavour	= $this->get('flavour');
		$id 		= $this->get('id');

		if ($id) {
			$id = explode(",", $id);
		}

		if (!$flavour) {
			$flavour = 'yousee';
		}
	
		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro);
			$profile_id = 'COREID';
		}

		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		$personid = $userinfo->userId;
		
		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid, $flavour);	
		}

		$validtypes = Array('movie', 'archive');
		if (!in_array($type, $validtypes)) {
			return $this->returnRestError(
				1033, 
				'Invalid type. Valid types: '.implode(", ", $validtypes),
				null,
				400
			); 
		}

		if (!$type) {
			return $this->returnRestError(
				1035, 
				'Mandatory parameters missing: type',
				null,
				400
			); 
		}	

		if ($flavour == 'tdc' && $type == 'movie') {
			$cookies = Facades\CoreID::getCookies($yspro);
			$sdc = new \OdpSdc\Sdc($cookies->ssoSessionDataValue, $cookies->ssoUserDataValue);
			$progresses = $sdc->getBookmarks();

			foreach ($progresses as $key => $progress) {
				$moviedata = $this->Movies->getMovie($progress->movieId, 'id');
				if (!$moviedata) {
					unset($progresses[$key]);
					continue;
				}
				$progresses[$key]->type = $type;
				$progresses[$key]->content = $progress->movieId;
				$progresses[$key]->markseconds = $progress->seconds;
				$progresses[$key]->create_time = date('Y-m-d H:i:s');
				$progresses[$key]->percentage = round(($progress->seconds/($moviedata['length']*60)*100), 0);
			}
		} else {
			$progresses = $this->User->getViewProgresses($personid, $type, $profile_id, $flavour);
		}

		$parsedProgresses = Array();

		foreach ($progresses as $progress) {
			if ($progress->percentage > 100) {
				$progress->percentage = 100;
			}
			if ($id && !in_array($progress->content, $id)) {
				continue;
			}
			
			$parsedProgresses[] = Array('type' => (string) $progress->type, 'id' => (string) $progress->content, 'seconds' => (int) $progress->markseconds, 'timestamp' => (string) $progress->create_time, 'percentage' => (int) $progress->percentage);
		}

		$this->response(Array('progresses' => $parsedProgresses), 200);
	}
	
	public function guestuser_get() {
		if (!empty($_REQUEST['DEBUG']) && $_REQUEST['DEBUG'] == '97') {
			$this->output->enable_profiler(TRUE);	
		}
		cacheHeaders(false);
		$this->load->model('User');
		$this->load->model('YSPro');
	
		$flavour = $this->get('flavour');
		$udid = ($this->get('u')) ? $this->get('u') : ((get_cookie('udid')) ? get_cookie('udid') : $this->get('drmclientid'));
		
		if (!$flavour) {
			$flavour = 'yousee';
		}
		
		$permissions = new \OdpPermissions\Channels(
			\OdpCaching\Memcache::getInstance(
				\OdpConfig\Config::getInstance()->getMemcacheServerpool()
			)
		);	
		
		$allowed_channels = Array();
		$hasArchive = false;

		if ($flavour == 'yousee') {
			$allowed_channels = $this->User->getAllowedChannels(false, false, false, $udid);
			$isAtHome = with(isUserAtHome('yousee', getClientIp()))->permission;		
			$hassvod = false; 
			$ottProducts = Array();
			$hasArchive = $this->User->hasCustomerSmartCard($this->User->getCustomerNoFromIp(getClientIp()));
			$hasPlus = $hasArchive;
		} else {
			$sdc = new \OdpSdc\Sdc(null, null);
			$allowed_channels = $permissions->getAllowedChannels('tdc', null, $sdc);
			$isAtHome = with(isUserAtHome('tdc', getClientIp()))->permission;		
			$hassvod = false;
			$hasPlus = false; 
			$hasArchive = (count($allowed_channels) && $isAtHome);
			$ottProducts = Array();
			$tvGuideChannelIds = $permissions->getTvGuideChannelsForTdcCustomer(null, $sdc, getClientIp(), true);
		}
		$facebookToken = null;
			
		$parsedAllowedChannels = $recordableChannels = Array();
		$hasDR1 = $hasZulu = $hasTV2 = $hasTCM = null; // used for determining if tv2 should be injected
		
		$extrachannelinfo = $this->config->item('extrachannelinfo');

		array_walk($allowed_channels, function($val) use(&$parsedAllowedChannels, &$hasDR1, &$hasTV2, &$hasTCM, &$hasZulu, &$recordableChannels, $extrachannelinfo) {
			if ($val == 1) { 
				$hasDR1 = true; 
			} 
			if ($val == 3) { 
				$hasTV2 = true; 
			} 
			if ($val == 4) { 
				$hasZulu = true; 
			} 
			if ($val == 22) { 
				$hasTCM = true; 
			} 
			$parsedAllowedChannels[] = (object) Array(
				"id" => $val, 
				"streamable" => true,	
				"name" => @$extrachannelinfo[$val]['nicename'],
				"logos" => (object) Array(
					"small" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$val]['small'],
					"large" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$val]['large'],
					"small_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$val]['small_seapp'],
					"large_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$val]['large_seapp']
				)
			);	
		});

		if ($hasDR1 && !$hasTV2 && $flavour == 'tdc') {
			$parsedAllowedChannels[] = (object) Array(
				"id" => 3, 
				"streamable" => false,
				"name" => @$extrachannelinfo[3]['nicename'],
				"logos" => (object) Array(
					"small" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[3]['small'],
					"large" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[3]['large'],
					"small_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[3]['small_seapp'],
					"large_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[3]['large_seapp']
				)
			);	
		}
		if ($hasZulu && !$hasTCM && $flavour == 'tdc') {
			$parsedAllowedChannels[] = (object) Array(
				"id" => 22, 
				"streamable" => false,
				"name" => @$extrachannelinfo[22]['nicename'],
				"logos" => (object) Array(
					"small" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[22]['small'],
					"large" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[22]['large'],
					"small_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[22]['small_seapp'],
					"large_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[22]['large_seapp']
				)
			);	
		}

		$tvGuideChannels = Array();
		
		if (count($tvGuideChannelIds) < 3 && count($parsedAllowedChannels) < 3) { // we need more than just youbio and infokanal
			$tvGuideChannelIds = Array(1,2,504,3,7,10,16,13,317,505,70,45,46,44,48,51,52,53,54,160); // grundpakke	
		}

		if (isset($tvGuideChannelIds) && is_array($tvGuideChannelIds)) {
			$sortAllowedChannels = $sortKey = Array();
			foreach ($tvGuideChannelIds as $channel) {
				if ($channel == 14 || $channel == 11) { 
					continue;
				}

				$tvGuideChannels[] = (object) Array(
					"id" => $channel,
					"name" => $extrachannelinfo[$channel]['nicename'],
					"logos" => (object) Array(
						"small" => 'http://cloud.yousee.tv/static/img/logos/'.$extrachannelinfo[$channel]['small'],
						"large" => 'http://cloud.yousee.tv/static/img/logos/'.$extrachannelinfo[$channel]['large'],
						"small_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.$extrachannelinfo[$channel]['small_seapp'],
						"large_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.$extrachannelinfo[$channel]['large_seapp']
					)
				);
				$sortKey[] = (array_search($channel, $allowed_channels) !== false) 
					? array_search($channel, $allowed_channels)
					: 1000;
			}

			if (count($sortKey) == count($tvGuideChannels)) {
				//array_multisort($sortKey, SORT_NUMERIC, SORT_ASC, $tvGuideChannels);
			}
		} else {
			foreach ($parsedAllowedChannels as $channel) {
				if ($channel->id == 14 || $channel->id == 11) { 
					continue;
				}
				$tvGuideChannels[] = (object) Array(
					"id" => $channel->id,
					"name" => $extrachannelinfo[$channel->id]['nicename'],
					"logos" => (object) Array(
						"small" => 'http://cloud.yousee.tv/static/img/logos/'.$extrachannelinfo[$channel->id]['small'],
						"large" => 'http://cloud.yousee.tv/static/img/logos/'.$extrachannelinfo[$channel->id]['large'],
						"small_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.$extrachannelinfo[$channel->id]['small_seapp'],
						"large_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.$extrachannelinfo[$channel->id]['large_seapp']
					)
				);
			}
		}

		$parsedProfiles = Array();

		$userdata = Array(	'firstname' => null,
							'lastname' => null,
							'email' => null,
							'username' => null,
							'tdc_external_id' => 0,
							'customerno' => null,
							'personid' => null,
							'hassvod' => (bool) $hassvod,
							'hasfacebooktoken' => (bool) $facebookToken,
							'hasdvr' => false,
							'hasarchive' => $hasArchive,
							'hasstartover' => (bool) $hasArchive, // startover follows archive
							'dvrrecordablechannels' => Array(),
							'ottproducts' => (array) $ottProducts,
							'allowedchannels' => $parsedAllowedChannels,
							'tvguidechannels' => $tvGuideChannels,
							'haspin' => (bool) false,
							'userisathome' => (bool) $isAtHome,
							'haspaymentmethod' => (bool) false,
							'profiles' => $parsedProfiles
						);			

		
		$this->response($userdata, 200);
	}
	
	public function user_get() {
		if (!empty($_REQUEST['DEBUG']) && $_REQUEST['DEBUG'] == '97') {
			$this->output->enable_profiler(TRUE);	
		}

		cacheHeaders(false);
		$this->load->model('User');
		$this->load->model('YSPro');
		$this->load->Model('Vip');
		$this->load->Model('Channels');

		$flavour = $this->get('flavour');
		$udid = ($this->get('u')) ? $this->get('u') : ((get_cookie('udid')) ? get_cookie('udid') : $this->get('drmclientid'));
		
		if (!$flavour) {
			$flavour = 'yousee';
		}
		
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		
		$cacheInstance = \OdpCaching\Memcache::getInstance(
			\OdpConfig\Config::getInstance()->getMemcacheServerpool()
		);

	 	$lastKnownUserInfoCacheKey = 'users-user-lastknownuserinfo-'.$yspro.'-'.getClientIp();

		if (
			$yspro &&
			$flavour != 'blockbuster' &&
			($lastKnownUserInfo = $cacheInstance->get($lastKnownUserInfoCacheKey)) &&
			date('H') >= 18 
		) {
			return $this->response($lastKnownUserInfo, 200);
		}

        $masterplan = null;

		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro, null, null, true);
            $masterplan = 'youbio';
        }
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro, null, null, true);
		}
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro, null, null, true);
            $masterplan = 'blockbuster';
		}
		if (!$userinfo) {
			$this->resolveCorrectSessionError();
			return;	
		}
	
		$permissions = new \OdpPermissions\Channels($cacheInstance);
		
		$personid = $userinfo->userId;
		if (
			$flavour != 'tdc' &&
			!in_array(
				$this->rest->key, 
				Array(
					'InhEiYCOUHquH8bmGKQSkZTqwxfx2jx3XuNZO4RS',
					'vkeXrZvghkTUfz7vYivoqcXm85sMVcdvrw8Ggxy0'
				)
			)
		) {	
			$haspaymentmethod = $this->User->hasUserValidPaymentMethod($personid, $masterplan);
		} else {
			$haspaymentmethod = false;
		}

		$statistics = null;
		$tvChannelPackage = null;
		$hasPlus = null;
		$allowed_channels = Array();
		$parsedAllowedChannels = $recordableChannels = Array();
		$usersettings = array();
		$hasPremiumHbo = $hasPremiumCmore = false;
		$smartCards = Array();
		$hasDvr = false;

		if ($flavour == 'yousee') {
			$allowed_channels = $this->User->getAllowedChannels(
				false, 
				false, 
				$personid, 
				$udid,
				false,
				(($this->get('flavour') == 'yousee') ? $userinfo->customerNumber : false), // clean up. remove check for flavour	
				($this->get('flavour') == 'yousee' && $personid), // if se_app AND logged in - don't merge
				($this->get('flavour')), // if se_app - don't use device
				$userinfo
			);
			
			$allowed_channels = $this->User->sortChannels($allowed_channels, $this->User->getChannelOrder(false, $userinfo->userId));

			$isAtHome = with(isUserAtHome('yousee', getClientIp(), $userinfo))->permission;		
			if (is_array($allowed_channels) && count($allowed_channels)) {
				$tvChannelPackage = with(new \OdpPermissions\TvChannelPackageResolver)
					->setChannels($allowed_channels)
					->resolvePackage();
			}

			$hassvod = $this->User->hasCustomerSvod($personid);
			$ottProducts = $this->User->getCustomerOttProducts($personid);
			$hasArchive = ($this->User->hasCustomerSmartCard($userinfo->customerNumber) || $this->Vip->hasAccess($personid, Vip::ARCHIVE));
			$hasDvr = false;
			$hasPlus = $hasArchive;
			$tvGuideChannelIds = $cableSubscriptionChannelIds = Array();

			if (!$userinfo->customerNumber) {
				// we need to check if the user is from dktv, to get the cablesubscriptionchannels
				$ysproInstance = new \OdpYspro\Yspro($cacheInstance);
				$dkTvAddressId = with(new \OdpPermissions\DkTv($cacheInstance, $ysproInstance, $userinfo))->getAddressId()->addressId;
			} else {
				$dkTvAddressId = null;
			}

			if ($userinfo->customerNumber || $dkTvAddressId) {
				$customerNumberToResolveChannelsFor = $userinfo->customerNumber ?: $dkTvAddressId;	
				
				$rawChannels = $this->User->getCustomerChannels($customerNumberToResolveChannelsFor);
				$tvGuideChannelIds = $this->Channels->getChannelIdsFromShortnames(explode("|", $rawChannels));
				
				// inject TV2 in tvguide. It is missing from masterdatabase feed
				// can be removed when SA-576 is resolved
				if (in_array(1, $tvGuideChannelIds) && !in_array(3, $tvGuideChannelIds)) {
					$tvGuideChannelIds[] = 3;
				}
				
				$tvGuideSortOrder = Array();
				foreach ($tvGuideChannelIds as $key => $tvGuideChannelId) {
					$tvGuideSortOrder[$key] = array_search($tvGuideChannelId, $this->config->item('preferredchannelorder'));
				}
				if (count($tvGuideSortOrder) === count($tvGuideChannelIds)) {
					array_multisort($tvGuideSortOrder, SORT_NUMERIC, SORT_ASC, $tvGuideChannelIds);
				}

				$tvGuideChannelIds = $this->User->sortChannels($tvGuideChannelIds, $this->User->getChannelOrder(false, $userinfo->userId));
			
				$cableSubscriptionChannelIds = $tvGuideChannelIds;
				
				$hasPremiumHbo = with(new \OdpPermissions\Hbo(
					$userinfo,
					null,
					$rawChannels))->getPermission('yousee');
				
				$hasPremiumCmore = with(new \OdpPermissions\Cmore(
					$userinfo,
					null,
					$rawChannels))->getPermission('yousee');
			} 
		} 
		else if ($flavour == 'tdc') {
			$cookies = Facades\CoreID::getCookies($yspro);
			if ($cookies) {
				$sdc = new \OdpSdc\Sdc($cookies->ssoSessionDataValue, $cookies->ssoUserDataValue);
				
				$hasDvr = with(new \OdpPermissions\Dvr)->hasDvr(
					'tdc', 
					$userinfo, 
					$sdc
				);
				
				$hasPremiumHbo = with(new \OdpPermissions\Hbo(
					$userinfo,
					$sdc
					))->getPermission('tdc');
				
				$hasPremiumCmore = with(new \OdpPermissions\Cmore(
					$userinfo,
					$sdc
					))->getPermission('tdc');
			} else {
				$sdc = new \OdpSdc\Sdc(null, null);
				$hasDvr = false;
			}
			$allowed_channels = $permissions->getAllowedChannels('tdc', ($userinfo) ? $userinfo : null, $sdc);
			
			$allowed_channels = $this->User->sortChannels($allowed_channels, $this->User->getChannelOrder(false, $userinfo->userId, 'tdc'));
			
			$isAtHome = with(isUserAtHome('tdc', getClientIp(), $userinfo))->permission;		
			$hassvod = false;
			
			$ottProducts = Array();
			$tvGuideChannelIds = $permissions->getTvGuideChannelsForTdcCustomer(
				$userinfo, 
				$sdc, 
				getClientIp(),
				true	
			);
			
			$tvGuideChannelIds = array_values(array_unique($tvGuideChannelIds));

			$tvGuideChannelIds = $this->User->sortChannels($tvGuideChannelIds, $this->User->getChannelOrder(false, $userinfo->userId, 'tdc'));
			// we need to run this again. We cannot allow global recording on SDC error
			// 4. parameter 
			$recordableChannels = $permissions->getTvGuideChannelsForTdcCustomer(
				$userinfo, 
				$sdc, 
				getClientIp(),
				false
			);
			
			$recordableChannels = array_values(array_unique($recordableChannels));

			// Webfacade backend does not allow recording on Regional 24 hour channels. Only 317 (Lorry)
			foreach ($recordableChannels as $key => $val) {
				if (in_array($val, Array(311,312,313,314,315,316,318))) {
					unset($recordableChannels[$key]);
				}
			}
			$recordableChannels = array_values($recordableChannels);	

			$hasArchive = $hasDvr;

		}
		else if ($flavour == 'blockbuster') {
			$hassvod = false;
			$isAtHome = false;
			$ottProducts = Array();
			$hasArchive = false;
			$tvGuideChannelIds = Array();

			$bookmarks = $this->User->getViewProgresses(
				$userinfo->userId, 
				'movie',	
				\Facades\BlockBusterLogin::getDefaultProfileId($userinfo->userId, 'blockbuster'),
				'blockbuster'
			);	

			$smartCards = with(new \OdpPermissions\DvbSmartcard)->getSmartcards($userinfo);

			$bookmarkMovieIds = Array();
			foreach ($bookmarks as $bookmark) {
				if ($bookmark->markseconds > 5) {
					$bookmarkMovieIds[] = $bookmark->content;	
				}
			}

			if (count($bookmarkMovieIds)) {
				$episodes = \Facades\VodRepo::getFromIds($bookmarkMovieIds, 'episode_id', 'episode_id', '>', 0, false, ($flavour == 'blockbuster')); 
 			} else {
				$episodes = Array();
			}
			$statistics = (object) Array('watched' => (object) Array('movies' => 0, 'episodes' => 0, 'trailers' => 0));

			$statistics->watched->movies = count($bookmarkMovieIds)-count($episodes);
			$statistics->watched->episodes = count($episodes);

			$settings = $this->User->getSettings($personid);
			$usersettings['newsletter'] = (($settings & User::SETTING_BB_PERMISSION_EMAIL) == User::SETTING_BB_PERMISSION_EMAIL);
		}
		
		if ($this->Vip->hasAccess($userinfo->userId, Vip::CMORE)) {
			$hasPremiumCmore = true;
		}
		if ($this->Vip->hasAccess($userinfo->userId, Vip::HBO)) {
			$hasPremiumHbo = true;
		}

		$facebookToken = ($flavour != 'tdc') ? $this->User->getAccessToken($personid, 'facebook') : null;
			
		$hasDR1 = $hasTV2 = $hasTCM = $hasZulu = null; // used for determining if tv2 and tcm should be injected
		
		$extrachannelinfo = $this->config->item('extrachannelinfo');

		array_walk($allowed_channels, function($val) use(&$parsedAllowedChannels, &$hasDR1, &$hasTV2, &$hasZulu, &$hasTCM, &$recordableChannels, $extrachannelinfo) {
			if ($val == 1) { 
				$hasDR1 = true; 
			} 
			if ($val == 3) { 
				$hasTV2 = true; 
			} 
			if ($val == 4) { 
				$hasZulu = true; 
			} 
			if ($val == 22) { 
				$hasTCM = true; 
			} 
			$parsedAllowedChannels[] = (object) Array(
				"id" => $val, 
				"name" => @$extrachannelinfo[$val]['nicename'],
				"streamable" => true,
				"logos" => (object) Array(
					"small" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$val]['small'],
					"large" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$val]['large'],
					"small_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$val]['small_seapp'],
					"large_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$val]['large_seapp']
				)
			);	
		});

		if ($hasDR1 && !$hasTV2 && $flavour == 'tdc') {
			$parsedAllowedChannels[] = (object) Array(
				"id" => 3, 
				"streamable" => false,
				"name" => @$extrachannelinfo[3]['nicename'],
				"logos" => (object) Array(
					"small" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[3]['small'],
					"large" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[3]['large'],
					"small_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[3]['small_seapp'],
					"large_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[3]['large_seapp']
				)
			);	
		}
		
		if ($hasZulu && !$hasTCM && $flavour == 'tdc') {
			$parsedAllowedChannels[] = (object) Array(
				"id" => 22, 
				"streamable" => false,
				"name" => @$extrachannelinfo[22]['nicename'],
				"logos" => (object) Array(
					"small" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[22]['small'],
					"large" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[22]['large'],
					"small_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[22]['small_seapp'],
					"large_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[22]['large_seapp']
				)
			);	
		}

		if ($flavour == 'yousee' && !$isAtHome && !$this->Vip->hasAccess($personid, Vip::TVWEBLARGE)) { // no tv2 when away
			foreach ($parsedAllowedChannels as $parsedAllowedChannel) {
				if ($parsedAllowedChannel->id == 3) {
					$parsedAllowedChannel->streamable = false;
				}
			}
		}

		$tvGuideChannelOrder = $tvGuideChannels = $cableSubscriptionChannels = Array();
		if (count($tvGuideChannelIds) < 3 && count($parsedAllowedChannels) < 3) { // we need more than just youbio and infokanal
			if ($flavour == 'tdc') {
				$tvGuideChannelIds = $permissions->defaultTdcChannelOrder;
			} else if ($this->get('flavour') == 'yousee') {
				$tvGuideChannelIds = $permissions->defaultChannelOrder;	
			}
		}
		
		if (isset($cableSubscriptionChannelIds) && is_array($cableSubscriptionChannelIds) && count($cableSubscriptionChannelIds)) {
			foreach ($cableSubscriptionChannelIds as $channel) {
				$cableSubscriptionChannels[] = (object) Array(
					"id" => $channel,
					"name" => @$extrachannelinfo[$channel]['nicename'],
					"logos" => (object) Array(
						"small" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel]['small'],
						"large" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel]['large'],
						"small_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel]['small_seapp'],
						"large_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel]['large_seapp']
					)
				);
			}
		} 

		if (isset($tvGuideChannelIds) && is_array($tvGuideChannelIds) && count($tvGuideChannelIds)) {
			foreach ($tvGuideChannelIds as $channel) {
				if ($channel == 14 || $channel == 11) { 
					continue;
				}

				$tvGuideChannels[] = (object) Array(
					"id" => $channel,
					"name" => @$extrachannelinfo[$channel]['nicename'],
					"logos" => (object) Array(
						"small" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel]['small'],
						"large" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel]['large'],
						"small_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel]['small_seapp'],
						"large_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel]['large_seapp']
					)
				);
				$tvGuideChannelOrder[] = $channel;
			}
		} else {
			foreach ($parsedAllowedChannels as $channel) {
				if ($channel->id == 14 || $channel->id == 11) { 
					continue;
				}
				$tvGuideChannels[] = (object) Array(
					"id" => $channel->id,
					"name" => @$extrachannelinfo[$channel->id]['nicename'],
					"logos" => (object) Array(
						"small" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel->id]['small'],
						"large" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel->id]['large'],
						"small_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel->id]['small_seapp'],
						"large_seapp" => 'http://cloud.yousee.tv/static/img/logos/'.@$extrachannelinfo[$channel->id]['large_seapp']
					)
				);
			}
		}
			
		$parsedProfiles = Array();

		if ($flavour == 'yousee') {	
			$defaultProfile = $this->YSPro->getDefaultProfileId($personid);
			$profiles = $this->YSPro->getUserProfiles($personid);

			foreach ($profiles->Data as $profile) {
				$parsedProfile = Array('profile_id' => (string) $profile->UUID);
				foreach ($profile->Properties as $property) {
					if ($property->DataName == 'Name') { $parsedProfile['name'] = (string) $property->Value; }
					if ($property->DataName == 'ImageURL') { $parsedProfile['avatar'] = (string) $property->Value; }
					if ($property->DataName == 'Default') { $parsedProfile['default'] = (bool) ($profile->UUID === $defaultProfile); }
				}
				$parsedProfiles[] = $parsedProfile;
			}
		}

  		$premiumSvodValue = 0;
		$premiumSvodValue += ($hasPremiumHbo) ? \OdpVodMeta\Dto\Movie::PREMIUMSVOD_HBO : 0;
		$premiumSvodValue += ($hasPremiumCmore) ? \OdpVodMeta\Dto\Movie::PREMIUMSVOD_CMORE : 0;
		$premiumSvodValue += ($hassvod) ? \OdpVodMeta\Dto\Movie::PREMIUMSVOD_YOUBIO : 0;

		$userdata = Array(	'firstname' => (string) $userinfo->firstname,
							'lastname' => (string) $userinfo->lastname,
							'email' => (string) $userinfo->email,
							'username' => (string) $userinfo->userLogin,
							'tdc_external_id' => 0,
							'customerno' => (int) $userinfo->customerNumber,
							'personid' => (int) $userinfo->userId,
							'phone' => (string) $userinfo->cellPhone,
							'facebookuserid' => (string) $userinfo->facebookUserId,
							'hassvod' => (bool) $hassvod,
							'hasfacebooktoken' => (bool) ($userinfo->facebookUserId || $facebookToken),
							'hasdvr' => (bool) $hasDvr,
							'hasarchive' => (bool) $hasArchive,
							'hasplus' => (bool) $hasPlus,
							'hasstartover' => (bool) $hasArchive, // startover follows archive
							'dvrrecordablechannels' => ($hasDvr) ? $recordableChannels : Array(),
							'ottproducts' => array_values($ottProducts),
							'allowedchannels' => $parsedAllowedChannels,
							'tvguidechannels' => $tvGuideChannels,
							'cablesubscriptionchannels' => $cableSubscriptionChannels,
							'tvchannelpackage' => $tvChannelPackage,
							'haspin' => (bool) false,
							'userisathome' => (bool) $isAtHome,
							'haspaymentmethod' => (bool) $haspaymentmethod,
							'profiles' => $parsedProfiles,
							'statistics' => $statistics,
							'smartcards' => $smartCards,
							'premiumsvod' => Array(
								"total" => $premiumSvodValue, 
								"hbo" => $hasPremiumHbo, 
								"cmore" => $hasPremiumCmore
							),
							'statistics' => $statistics,
							'newsletter' => isset($usersettings['newsletter']) ? $usersettings['newsletter'] : null
						);

		$cacheInstance->set(
			$lastKnownUserInfoCacheKey,
			$userdata
		);	

		$this->response($userdata, 200);
	}
	
	public function movielog_post() {
		cacheHeaders(false);
		$this->load->model('YSPro');
		$this->load->model('User');
	
		$yspro = ($this->post('yspro')) ? $this->post('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$userinfo = $this->YSPro->getUserInfo($yspro);
		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		$userinfo = explode("|", $userinfo);
		$personid = $userinfo[0];
	
		$id = $this->post('id');
		$progress = $this->post('progress');
		$profile_id = $this->post('profile_id');

		if (!$id || !$progress) {
			return $this->returnRestError(
				1035, 
				'Mandatory parameters missing: id, progress',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}	
		
		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid);	
		}
	
		
		if ($progress > 100) {$progress = 100; }
		if ($progress < 0) {$progress = 0; }

		$status = $this->User->registerMovieLog($personid, $id, $progress, $profile_id);
	
		if ($status) {
			$this->response(Array('status' => 'ok'), 200);	
		} else {
			return $this->returnRestError(
				1027, 
				'System error',
				null,
				500,
				false,
				true,
				$userinfo
			); 
		}
	}
	public function movielog_get() {
		cacheHeaders(false);
		$this->load->model('YSPro');
		$this->load->model('User');
		$this->load->model('Movies');
	
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$limit = $this->get('limit');
		$profile_id = $this->get('profile_id');


		$userinfo = $this->YSPro->getUserInfo($yspro);
		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		$userinfo = explode("|", $userinfo);
		$personid = $userinfo[0];
		
		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid);	
		}

		$movielog = Array();
		$events = $this->User->getMovieLog($personid, $limit, false, $profile_id);

		foreach ($events as $event) {
			$moviedata = $this->Movies->getMovie($event->content, 'id');
			if (!$moviedata || !$moviedata['active_ott']) { continue; }
			$movielog[] = Array('id' => (string) $event->content, 'progress' => (int) $event->progress, 'timestamp' => (string) $event->create_time);
		}

		$this->response(Array('movielog' => $movielog), 200);	
	}
	
	public function movielog_delete() {
		cacheHeaders(false);
		$this->load->model('YSPro');
		$this->load->model('User');
	
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$userinfo = $this->YSPro->getUserInfo($yspro);
		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		$userinfo = explode("|", $userinfo);
		$personid = $userinfo[0];

		$profile_id = $this->get('profile_id');
		
		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid);	
		}

		$status = $this->User->resetMovieLog($personid, $profile_id);

		if ($status) {
			$this->response(Array('status' => 'ok'), 200);	
		} else {
			return $this->returnRestError(
				1027, 
				'System error',
				null,
				500,
				false,
				true,
				$userinfo
			); 
		}
	}

	public function channel_order_get() {
		cacheHeaders(false);
		$this->load->model('User');
	
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$flavour = $this->get('flavour');

		if (!$flavour) {
			$flavour = 'yousee';
		}
	
		$userinfo = null;

		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro);
		}
		
		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		$channelOrder = $this->User->getChannelOrder(false, $userinfo->userId, $flavour);
		if (!$channelOrder) {
			$this->response(Array('order' => $this->config->item('preferredchannelorder')), 200);
		} else {
			foreach ($channelOrder as $key => $channel) {
				$channelOrder[$key] = (int) $channel;
			}
			$this->response(Array('order' => $channelOrder), 200);
		}
	}
	
	public function channel_order_post() {
		cacheHeaders(false);
		$this->load->model('User');
	
		$yspro = ($this->post('yspro')) ? $this->post('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$order = $this->post('order');
		$flavour = $this->post('flavour');

		if (!$flavour) {
			$flavour = 'yousee';
		}
		
		$userinfo = null;

		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'tdc') {
			$userinfo = Facades\CoreID::getUserInfo($yspro);
		}
		
		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		if (!$order) {
			return $this->returnRestError(
				1008, 
				'Mandatory parameter missing: order',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}

		$this->User->saveChannelOrder($userinfo->userId, $order, $flavour);

		$this->response(Array('status' => 'ok'), 200);
		return;
	}

	public function bookmarks_delete() {
		cacheHeaders(false);
		$this->load->model('YSPro');
		$this->load->model('User');
	
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$userinfo = $this->YSPro->getUserInfo($yspro);
		if (!$userinfo) {
			return $this->returnRestError(
				1024, 
				'Invalid user session',
				null,
				400
			); 
		}
		
		$userinfo = explode("|", $userinfo);
		$personid = $userinfo[0];

		$status = $this->User->resetViewProgresses($personid);

		if ($status) {
			$this->response(Array('status' => 'ok'), 200);	
		} else {
			return $this->returnRestError(
				1027, 
				'System error',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}
	}

	public function filmshelf_get() {
		cacheHeaders(false);
		$this->load->model('YSPro');
		$this->load->model('User');
		$this->load->model('Transaction');
		$this->load->model('Movies');
		
		$apikey = $this->rest->key;
	
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$userinfo = $this->YSPro->getUserInfo($yspro);
		if (!$userinfo) {
			$this->response(Array('errorcode' => 1024, 'error' => 'Invalid user session'), 400);
			return;	
		}
		
		$profile_id = $this->get('profile_id');
		
		$userinfo = explode("|", $userinfo);
		$personid = $userinfo[0];
	
		if (!$profile_id) {
			$profile_id = $this->YSPro->getDefaultProfileId($personid);	
		}

		$bookmarks = $this->User->getViewProgresses($personid, 'movie', $profile_id);
		$movielog = $this->User->getMovieLog($personid, false, false, $profile_id);
		
		$partnerkey = (!empty($this->moviepartners[$apikey]['partnerkey'])) ? $this->moviepartners[$apikey]['partnerkey'] : 'yousee.tv';
		$transactions = $this->Transaction->getUserTransactionLog($personid, false, false, true, $partnerkey);

		$parsedBookmarks = $parsedMovielog = $parsedTransactions = Array();

		foreach ($bookmarks as $bookmark) {
			if ($bookmark->type == 'movie') {
				$moviedata = $this->Movies->getMovie($bookmark->content, 'id');
				if (!$moviedata || !$moviedata['active_ott']) { continue; }
			}
			$parsedBookmarks[] = Array('type' => (string) $bookmark->type, 'id' => (string) $bookmark->content, 'seconds' => (int) $bookmark->markseconds, 'timestamp' => (string) $bookmark->create_time);
		}

		foreach ($movielog as $event) {
			$moviedata = $this->Movies->getMovie($event->content, 'id');
			if (!$moviedata || !$moviedata['active_ott']) { continue; }
			$parsedMovielog[] = Array('id' => (string) $event->content, 'progress' => (int) $event->progress, 'timestamp' => (string) $event->create_time);
		}
		
		foreach ($transactions as $transaction) {
			if (time() > strtotime($transaction['expires'])) { continue; }
			if ($transaction['type'] == 'livetv') { continue; } 
			if ($transaction['type'] == 'movie') {
				$moviedata = $this->Movies->getMovie($transaction['product_id'], 'id');
				if (!$moviedata || !$moviedata['active_ott']) { continue; }
			}
			$parsedTransactions[] = Array('id' => (string) $transaction['product_id'], 'expiry' => (string) $transaction['expires'], 'timestamp' => (string) $transaction['createtime'], 'type' => $transaction['type']);
		}

		$this->response(Array('bookmarks' => $parsedBookmarks, 'movielog' => $parsedMovielog, 'transactions' => $parsedTransactions), 200);
	}

	public function sharedshelf_get()
	{
		cacheHeaders(false);

		$this->load->Model('Transaction');
		
		$smartcard = $this->get('smartcard');
		$flavour = $this->get('flavour');
		$fields = $this->get('fields');

		if (!$flavour) {
			$flavour = 'yousee';
		}

		if (!$smartcard) {	
			return $this->returnRestError(
				1008, 
				'Mandatory parameter missing: socialnetwork, yspro',
				null,
				400
			); 
		}

		if ($flavour != 'blockbuster') {
			return $this->returnRestError(
				1058, 
				'Currently only supported for blockbuster',
				null,
				400
			); 
		}
		
		$userId = with(new \OdpPermissions\DvbSmartcard)->getUserIdForSmartcard($smartcard);

		if (!$userId) {
			return $this->response(Array('movies' => Array(), 'total' => 0, 'note' => 'unknown smartcard'), 200);
		}

		$transactions = $this->Transaction->getUserTransactionLog($userId, false, false, false, 'blockbuster', true);
	
		$touchedTransactions = Array();

		foreach ($transactions as $transaction) {
            $pay_action = $transaction['pay_action'];

			if ($transaction['started'] && $pay_action == 'RENT') {
				if ((strtotime($transaction['started'])+$this->config->item('rental_period')) < time()) {
					continue;
				}
			}
			
			if (isset($touchedTransactions[$transaction['product_id']])) {
				continue;
			} else {
				$touchedTransactions[$transaction['product_id']] = true;	
			}
			
			$items[] = Array(
				'id' => $transaction['product_id'], 
				'timestamp' => $transaction['createtime'], 
				'activitytype' => strtolower("transaction_$pay_action")
			);
		}

		$sortKey = Array();
		foreach ($items as $key => $item) {
			$sortKey[$key] = strtotime($item['timestamp']);
		}

		array_multisort($sortKey, SORT_NUMERIC, SORT_DESC, $items);

		$itemObjects = $movieIds = Array();

		array_walk($items, function($val) use(&$movieIds) {
			$movieIds[] = $val['id'];
		});

		if (count($movieIds)) {
			$movieData = Facades\VodRepo::getFromIds($movieIds, '*', null, null, null, ($flavour == 'blockbuster'), ($flavour == 'blockbuster'));
		}

        $touchedTvSeriesSeasons = Array();

		foreach ($items as $item) {
			$movie = $this->findMovieData($item['id'], $movieData);
			if (!$movie) {
				continue;
			}
			$movie->genres = Facades\VodRepo::getGenresForMovie($movie->id);

			$movieDto = new \OdpVodMeta\Dto\Movie(
				$movie,
				\OdpConfig\Config::getInstance(),
				new \OdpPopularity\Vod(Facades\VodRepo::getInstance()),
				Facades\VodRepo::getInstance(),
				$flavour
			);

            if ($movieDto->assettype == 'episode') {
                $tvSeriesSeasonIdentifier = $movieDto->episodeinfo->seasonid.$item['activitytype'];
				if (isset($touchedTvSeriesSeasons[$tvSeriesSeasonIdentifier])) {
                    continue;
                } else {
                    $touchedTvSeriesSeasons[$tvSeriesSeasonIdentifier] = true;
                }
            }
	
			$movieDto->activity = (object) Array(
				"_type" => $item['activitytype'],
				"timestamp" => $item['timestamp'],
				"unixtimestamp" => strtotime($item['timestamp'])
			);
			if ($fields) {
				$filtering = new OdpOutput\Filtering;
				$movieDto = $filtering->filter(
					$filtering->prepareFields($fields),
					$movieDto
				);	
			}
			$itemObjects[] = $movieDto;
		}
		
		return $this->response(Array('movies' => $itemObjects, 'total' => count($itemObjects)), 200);
	}
	
	public function socialregistration_delete() {	
		cacheHeaders(false);
		
		$yspro = ($this->delete('yspro')) ? $this->delete('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		if (!$yspro) {
			$yspro = $this->get('yspro');
		}

		$flavour	= ($this->get('flavour')) ? $this->get('flavour') : $this->delete('flavour');
		$socialnetwork	= ($this->get('socialnetwork')) ? $this->get('socialnetwork') : $this->delete('socialnetwork');

		if (!$flavour) {
			$flavour = 'yousee';
		}

		if (!$socialnetwork || !$yspro) {
			return $this->returnRestError(
				1008, 
				'Mandatory parameter missing: socialnetwork, yspro',
				null,
				400
			); 
		}
	
		$status = false;

		if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
			
			if (!$userinfo) {
				return $this->returnRestError(
					1024, 
					'Invalid user session',
					null,
					400
				); 
			}

			$status = Facades\BlockBusterLogin::disconnectFacebookId(
				$yspro
			);	
			
			// flush cache
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro, null, null, true);

			$this->response(Array('status' => (bool) $status), 200);
		} else {
			$this->response(Array('status' => (bool) $status), 200);
		}
	}
	
	public function socialregistration_post() {	
		cacheHeaders(false);
		
		$this->load->model('User');
		$this->load->model('YSPro');
	
		$token 			= $this->post('token');
		$socialnetwork 	= $this->post('socialnetwork');
		$yspro = ($this->post('yspro')) ? $this->post('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		$flavour = $this->post('flavour');

		if (!$flavour) {
			$flavour = 'yousee';
		}

		if (!$token || !$socialnetwork || !$yspro) {
			return $this->returnRestError(
				1008, 
				'Mandatory parameter missing: token, socialnetwork, yspro',
				null,
				400
			); 
		}
	
		if ($flavour == 'yousee') {
			$userinfo = $this->YSPro->getUserInfo($yspro);
				
			if (!$userinfo) {
				return $this->returnRestError(
					1024, 
					'Invalid user session',
					null,
					400
				); 
			}
				
			$userinfo = explode("|", $userinfo);
			$personid = $userinfo[0];

			$permissions = $this->User->getProviderPermissionsFromToken($token, $socialnetwork);

			if (!$permissions || !$permissions->data || (!$permissions->data[0]->publish_stream || !$permissions->data[0]->publish_actions)) {
				return $this->returnRestError(
					1041, 
					'Token does not have the correct permissions (publish_stream or publish_actions)',
					null,
					400
				); 
			}

			$status = $this->User->setAccessToken($personid, $socialnetwork, $token);

			$this->response(Array('status' => (bool) $status), 200);
		}
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
			
			if (!$userinfo) {
				return $this->returnRestError(
					1024, 
					'Invalid user session',
					null,
					400
				); 
			}

			$status = Facades\BlockBusterLogin::setFacebookId(
				$yspro,
				$token
			);	
			
			// flush cache
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro, null, null, true);

			if (!$status) {
				$presentableError = (Facades\BlockBusterLogin::getInstance()->lastError == 90) 
					? 'Facebook kontoen er allerede tilknyttet en anden Blockbuster konto'
					: 'Facebook kontoen kunne desværre ikke tilknyttes din Blockbuster konto';
				
				return $this->returnRestError(
					1054,
					'Socialregistration failed',
					$presentableError,
					409,
					false,
					true,
					$userinfo
				);
			}

			$this->response(Array('status' => (bool) $status), 200);
		}
	}
	
	public function socialregistration_get() {	
		cacheHeaders(false);
		
		$token 			= $this->get('token');
		$socialnetwork 	= $this->get('socialnetwork');
		
		if (!$token || !$socialnetwork) {
			return $this->returnRestError(
				1008, 
				'Mandatory parameter missing: token, socialnetwork',
				null,
				400
			); 
		}

		$this->load->model('User');
		$personid = $this->User->getPersonIdForToken($socialnetwork, $token);

		$this->response(Array('status' => (bool) $personid), 200);
	}

	
	public function socialactivity_post() {	
		cacheHeaders(false);
		$this->load->model('NodesAPI');
		$this->load->model('YSPro');
		$this->load->model('User');
		
		$token 			= $this->post('token');
		$socialnetwork 	= $this->post('socialnetwork');
		$type			= $this->post('type');
		$id 			= $this->post('id');
		
		if (!$token) {
			$yspro = ($this->post('yspro')) ? $this->post('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
			$userinfo = $this->YSPro->getUserInfo($yspro);
		
			if (!$userinfo) {
				return $this->returnRestError(
					1024, 
					'Invalid user session',
					null,
					400
				); 
			}
		
			$userinfo = explode("|", $userinfo);
			$personid = $userinfo[0];
		
			if (!(int) $personid) {
				return $this->returnRestError(
					1024, 
					'Invalid user session',
					null,
					400
				); 
			}
			$token = $this->User->getAccessToken($personid, 'facebook'); 
		}	

		if (!$token) {
			return $this->returnRestError(
				3023, 
				'Missing parameter. Mandatory parameters: token',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}	
		
		if (!$token || !$socialnetwork || !$type || !$id) {
			return $this->returnRestError(
				1008, 
				'Mandatory parameter missing: token, socialnetwork, type, id',
				null,
				400,
				false,
				true,
				$userinfo
			); 
		}

		if ($socialnetwork == 'facebook') {
			if ($type == 'movie') {
				$status = $this->NodesAPI->postActivity($token, $id, $type);
			}
		}
	
		$this->response(Array('status' => (bool) $status), 200);
	
	}

	public function devicetoken_post() {
		cacheHeaders(false);
		$this->load->Model('PushNotifications');
		
		$this->load->model('User');
		$this->load->model('YSPro');
	
		$token 			= $this->post('token');
		$platform		= $this->post('platform');
		$yspro 			= ($this->post('yspro')) ? $this->post('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
	
		if (!$token || !$platform || !$yspro) {
			$this->response(Array('errorcode' => 1008, 'error' => 'Mandatory parameter missing: token, platform, yspro'), 400);
			return;
		}

		if ($platform != 'gcm' && $platform != 'apns') {
			$this->response(Array('errorcode' => 1040, 'error' => 'Unknown platform. Valid platforms are: gcm, apns'), 400);
			return;
		
		}
		
		$userinfo = $this->YSPro->getUserInfo($yspro);
		
		if (!$userinfo) {
			$this->response(Array('errorcode' => 1024, 'error' => 'Invalid user session'), 400);
			return;	
		}
		
		$userinfo = explode("|", $userinfo);
		$personid = $userinfo[0];

		$status = $this->PushNotifications->addPushToken($personid, $token, $platform);
		
		$this->response(Array('status' => (bool) $status), 200);
	}
	
	public function devicetoken_delete() {
		cacheHeaders(false);
		$this->load->Model('PushNotifications');
		
		$this->load->model('User');
		$this->load->model('YSPro');
	
		$token 			= $this->get('token');
		$platform		= $this->get('platform');
		$yspro 			= ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
	
		if (!$token || !$platform || !$yspro) {
			$this->response(Array('errorcode' => 1008, 'error' => 'Mandatory parameter missing: token, socialnetwork, yspro'), 400);
			return;
		}

		if ($platform != 'gcm' && $platform != 'apns') {
			$this->response(Array('errorcode' => 1040, 'error' => 'Unknown platform. Valid platforms are: gcm, apns'), 400);
			return;
		}
		
		$userinfo = $this->YSPro->getUserInfo($yspro);
		
		if (!$userinfo) {
			$this->response(Array('errorcode' => 1024, 'error' => 'Invalid user session'), 400);
			return;	
		}
		
		$userinfo = explode("|", $userinfo);
		$personid = $userinfo[0];

		$status = $this->PushNotifications->removePushToken($personid, $token, $platform);
		
		$this->response(Array('status' => (bool) $status), 200);
	}

	public function activitystream_get()
	{
		cacheHeaders(false);
	
		$this->load->Model('User');
		$this->load->Model('Userlists');
		$this->load->Model('Transaction');

		$flavour = $this->get('flavour');
		$fields = $this->get('fields');
		$yspro = ($this->get('yspro')) ? $this->get('yspro') : ($this->input->server('HTTP_X_YSPRO') ? $this->input->server('HTTP_X_YSPRO') : get_cookie('yspro'));
		if (!$flavour) {
			$flavour = 'yousee';
		}

		$userinfo = null;

		if ($flavour == 'yousee') {
			$userinfo = Facades\YSPRO::getUserInfo($yspro);
	 	} 
		else if ($flavour == 'blockbuster') {
			$userinfo = Facades\BlockBusterLogin::getUserInfo($yspro);
	 	} 

		if (!$userinfo) {
			return $this->resolveCorrectSessionError();
		}

		if ($flavour == 'yousee') {
			$profile_id = Facades\YSPRO::getDefaultProfileId($userinfo->userId, $flavour);
		}
		else if ($flavour == 'blockbuster') {
			$profile_id = Facades\BlockBusterLogin::getDefaultProfileId($userinfo->userId, $flavour);
		}
		
		$items = Array();

		$lists = $this->Userlists->getLists($userinfo->userId, 'movies', $profile_id, $flavour);

		$touchedFavorites = Array();

		if (count($lists)) {
			$rawitems = $this->Userlists->getItemsInList($lists[0]['id'], true);
			if ($rawitems && is_array($rawitems) && count($rawitems)) {
				foreach ($rawitems as $item) {
					if (!empty($touchedFavorites[$item['track_id']])) {
						continue;
					}
					$items[] = Array('id' => $item['track_id'], 'timestamp' => $item['create_time'], 'activitytype' => 'favorite');	
					$touchedFavorites[$item['track_id']] = true;
				}
			}
		}

		$transactions = $this->Transaction->getUserTransactionLog($userinfo->userId, false, false, false, 'blockbuster', true);

		$dvbPurchases = with(new \OdpPermissions\DvbSmartcard)->getSmartcardPurchasesForUser($userinfo);
		if (count($dvbPurchases)) {
			foreach ($dvbPurchases as $dvbPurchase) {
				$transactions[] = Array(
					'pay_action' => 'RENT',
					'started' => date('Y-m-d H:i:s', $dvbPurchase->start),
					'product_id' => $dvbPurchase->id,
					'createtime' => date('Y-m-d H:i:s', $dvbPurchase->start)	
				);
			}
		}

		$touchedTransactions = Array();

		foreach ($transactions as $transaction) {
            $pay_action = $transaction['pay_action'];

			if ($transaction['started'] && $pay_action == 'RENT') {
				if ((strtotime($transaction['started'])+$this->config->item('rental_period')) < time()) {
					continue;
				}
			}
			
			if (isset($touchedTransactions[$transaction['product_id']])) {
				continue;
			} else {
				$touchedTransactions[$transaction['product_id']] = true;	
			}
			
			$items[] = Array('id' => $transaction['product_id'], 'timestamp' => $transaction['createtime'], 'activitytype' => strtolower("transaction_$pay_action"));
		}

		$sortKey = Array();
		foreach ($items as $key => $item) {
			$sortKey[$key] = strtotime($item['timestamp']);
		}

		array_multisort($sortKey, SORT_NUMERIC, SORT_DESC, $items);

		$itemObjects = $movieIds = Array();

		array_walk($items, function($val) use(&$movieIds) {
			$movieIds[] = $val['id'];
		});

		if (count($movieIds)) {
			$movieData = Facades\VodRepo::getFromIds($movieIds, '*', null, null, null, ($flavour == 'blockbuster'), ($flavour == 'blockbuster'));
		}

        $touchedTvSeriesSeasons = Array();

		foreach ($items as $item) {
			$movie = $this->findMovieData($item['id'], $movieData);
			if (!$movie) {
				continue;
			}
			$movie->genres = Facades\VodRepo::getGenresForMovie($movie->id);

			$movieDto = new \OdpVodMeta\Dto\Movie(
				$movie,
				\OdpConfig\Config::getInstance(),
				new \OdpPopularity\Vod(Facades\VodRepo::getInstance()),
				Facades\VodRepo::getInstance(),
				$flavour
			);

            if ($movieDto->assettype == 'episode') {
                $tvSeriesSeasonIdentifier = $movieDto->episodeinfo->seasonid.$item['activitytype'];
				if (isset($touchedTvSeriesSeasons[$tvSeriesSeasonIdentifier])) {
                    continue;
                } else {
                    $touchedTvSeriesSeasons[$tvSeriesSeasonIdentifier] = true;
                }
            }
	
			$movieDto->activity = (object) Array(
				"_type" => $item['activitytype'],
				"timestamp" => $item['timestamp'],
				"unixtimestamp" => strtotime($item['timestamp'])
			);
			if ($fields) {
				$filtering = new OdpOutput\Filtering;
				$movieDto = $filtering->filter(
					$filtering->prepareFields($fields),
					$movieDto
				);	
			}
			$itemObjects[] = $movieDto;
		}

		$this->response(Array('items' => $itemObjects), 200);
	}

	private function addOnboardingMoviesToBlockbusterUser($userId, $username, $emailAddress)
	{
		// blockbuster promotion videos
		$onboardMovieIds = \OdpConfig\Config::getInstance()->getBlockbusterOnBoardingMovieIds();

		if (is_array($onboardMovieIds) && count($onboardMovieIds)) {
			foreach ($onboardMovieIds as $onboardMovieId) {
				$movieData = \Facades\VodRepo::getFromIds(Array($onboardMovieId), 'title,provider');
				if (is_array($movieData) && count($movieData)) {
					$partnerReference = 'onboard-'.time().'-'.mt_rand(1000,9999);
					$movieData = current($movieData);
					$orderId =  $this->Transaction->create(
						$userId,
						'movie',
						$movieData->title,
						$onboardMovieId,
						$username,
						$emailAddress,
						0,
						30,
						$movieData->provider,
						'',
						false,
						'blockbuster',
						$partnerReference,
						'',
                        null /* $num_clip */, null /* $clipcard_product_id */, null /* $clipcard_ref */, null /* $clipcard_clip_id */,
                        'RENT'
					);

					if ($orderId) {
						$this->Transaction->complete(
							$orderId,
							0
						);	
					} 					
				}
			}	
		}	
		return true;
	}

	private function logrequest($method, $payload, $response, $errorcode) {
		return true;
		$data = Array();
		$data['id'] = uniqid(true);
		$data['endpoint'] = $_SERVER['REQUEST_URI'];
		$data['method'] = $method;
		$data['payload'] = $payload;
		$data['response'] = $response;
		$data['errorcode'] = $errorcode;
		$data['apikey'] = $this->rest->key;
		$data['ipaddress'] = $this->input->ip_address();

		$this->db->insert('log_rest', $data);
	}

	private function findMovieData($id, $movieData) 
	{
		foreach ($movieData as $movie) {
			if ($id == $movie->id) {
				return $movie;
			}
		}

		return false;
	}

	private function getTechnology() {
		$apikey = $this->get('API-Key');
	
		$flash = Array(	'bbvOggcU8Md0NFL1yzHj491ttX4ayu28RIFEH0s6',
						'VSA6699BuZC7nNo9IXhKg6Pt0WwLQHQJ8mvSHROi',
						'CYc4SMPLsa5YyKcHqqXt6zBZzYnuuO0BeNAJunti');

		if (in_array($apikey, $flash)) { return 'flash'; }
		else { return 'hls'; }
	}
	
	private function resolveCorrectSessionError() 
	{
		$tdcError = Facades\CoreID::getLastTdcError();
		if ($tdcError) {
			if ($tdcError->code == 2) {
				return $this->returnRestError(
					1046, 
					'Invalid user session',
					'Dit login er spærret i 12 timer, da du har forsøgt at logge på med forkert adgangskode 10 gange',
					400
				); 
			}
			else if ($tdcError->code == 5) {
				return $this->returnRestError(
					1046, 
					'Invalid user session',
					'Det tilladte antal samtidige logins er overskredet',
					400
				); 
			}
		}
		return $this->returnRestError(
			1024, 
			'Invalid user session',
			null,
			400
		); 
	}

}

?>
