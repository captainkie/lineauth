<?php

namespace LineAuth\Provider;

use Symfony\Component\HttpFoundation\Session\Session;

/**
 * Line OAuth2.
 */
class Line
{
		protected $scope = 'openid email profile';
    protected $apiBaseUrl = 'https://access.line.me/oauth2/v2.1';
    protected $authorizeUrl = 'https://access.line.me/oauth2/v2.1/authorize?';
    protected $accessTokenUrl = 'https://api.line.me/oauth2/v2.1/token';
		protected $apiDocumentation = 'https://developers.line.me/en/services/line-login';
		protected $verifyingTokensUrl = 'https://api.line.me/oauth2/v2.1/verify';
		protected $revokeTokensUrl = 'https://api.line.me/oauth2/v2.1/revoke';
		protected $refreshTokensUrl = 'https://api.line.me/oauth2/v2.1/token';

		private $config = [
			'response_type' => 'code',
			'client_id' => NULL,
			'client_secret' => NULL,
			'redirect_uri' => NULL,
			'state_key' => 'line_rand_state_token',
		];

		private $session;

		public function __construct($config = NULL) {
			$this->session = new Session();
			$this->config = $config;
		}

		public function authenticate($provider = 'Line')
    {		
			$this->session->set($this->config['state_key'], $this->randomToken());
			$this->session->get($this->config['state_key']);

			$url = $this->authorizeUrl . http_build_query(
				[
					'response_type' => $this->config['response_type'],
					'client_id' => $this->config['client_id'],
					'redirect_uri' => $this->config['redirect_uri'],
					'scope' => $this->scope,
					'state' => $this->session->get($this->config['state_key'])
				]
			);
			
			$this->redirect($url);
		}

		public function getAccessToken($params = [], $ssl = NULL)
    {     
			$header = ['Content-Type: application/x-www-form-urlencoded'];    
      $body = [
				'grant_type' => $params['grant_type'],
				'code' => (string) $params['code'],
				'redirect_uri' => $this->config['redirect_uri'],
				'client_id' => $this->config['client_id'],
				'client_secret' => $this->config['client_secret']
			];       

			$dataToken = $this->callLineApi('post', $this->accessTokenUrl, $header, $body, $ssl);

			return $dataToken;
		}
		
		public function veritifyAccessToken($params = [], $ssl = NULL)
		{
			$header = ['Content-Type: application/x-www-form-urlencoded'];    
      $body = [
				'access_token' => $params['tokens']
			];       
			$dataToken = $this->callLineApi('get', $this->verifyingTokensUrl, $header, $body, $ssl);

			return $dataToken;
		}

		public function revokeAccessToken($params = [], $ssl = NULL)
		{
			$header = ['Content-Type: application/x-www-form-urlencoded'];    
      $body = [
				'access_token' => $params['tokens'],
				'client_id' => $this->config['client_id'],
				'client_secret' => $this->config['client_secret']
			];       
			$dataToken = $this->callLineApi('post', $this->revokeTokensUrl, $header, $body, $ssl);

			return $dataToken;
		}

		public function refreshAccessToken($params = [], $ssl = NULL)
		{
			$header = ['Content-Type: application/x-www-form-urlencoded'];    
      $body = [
				'grant_type' => 'refresh_token',
				'code' => (string) $params['refresh_token'],
				'client_id' => $this->config['client_id'],
				'client_secret' => $this->config['client_secret']
			];       
      
			$dataToken = $this->callLineApi('post', $this->refreshTokensUrl, $header, $body, $ssl);

			return $dataToken;
		}

		private function callLineApi($type, $url, $headers, $data, $ssl)
    { 
			$curl = curl_init();

			if($type == 'get'){	
				curl_setopt_array($curl, array(
					CURLOPT_URL => $url."?".http_build_query($data),
					CURLOPT_CUSTOMREQUEST => "GET",
					CURLOPT_HTTPHEADER => $headers,
					CURLOPT_SSL_VERIFYHOST => (isset($ssl)) ? 2 : 0,
					CURLOPT_SSL_VERIFYPEER => (isset($ssl)) ? 1 : 0,
					CURLOPT_FOLLOWLOCATION => true,
					CURLOPT_RETURNTRANSFER => true,
					CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1					
				));
			} else {
				curl_setopt_array($curl, array(
					CURLOPT_URL => $url,
					CURLOPT_POST => true,
					CURLOPT_POSTFIELDS => http_build_query($data),
					CURLOPT_HTTPHEADER => $headers,
					CURLOPT_SSL_VERIFYHOST => (isset($ssl)) ? 2 : 0,
					CURLOPT_SSL_VERIFYPEER => (isset($ssl)) ? 1 : 0,
					CURLOPT_FOLLOWLOCATION => true,
					CURLOPT_RETURNTRANSFER => true,
					CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1
				));
			}
     
			$response = curl_exec($curl);
			$err = curl_error($curl);
			$httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
			curl_close($curl);

			return $result = json_decode($response, TRUE);
		}
		
		private function redirect($url)
    {
			if(!header("Location: {$url}")){
				echo '<meta http-equiv="refresh" content="0;URL=$url">';
			}	exit;       
    }
		
		private function randomToken($length = 32)
    {
			if(!isset($length) || intval($length) <= 8 ){
				$length = 32;
			}
			if(function_exists('random_bytes')) {
				return bin2hex(random_bytes($length));
			}
			if(function_exists('mcrypt_create_iv')) {
				return bin2hex(mcrypt_create_iv($length, MCRYPT_DEV_URANDOM));
			} 
			if(function_exists('openssl_random_pseudo_bytes')) {
				return bin2hex(openssl_random_pseudo_bytes($length));
			}
    }
}
