<?php

namespace LineAuth\Provider;

//use \Firebase\JWT\JWT;

/**
 * Line OAuth2.
 */
class Line
{
		protected $scope = 'openid email profile';
    protected $apiBaseUrl = 'https://access.line.me/oauth2/v2.1';
    protected $authorizeUrl = 'https://access.line.me/oauth2/v2.1/authorize';
    protected $accessTokenUrl = 'https://api.line.me/oauth2/v2.1/token';
		protected $apiDocumentation = 'https://developers.line.me/en/services/line-login';
		private $config = [];
		
		public function __construct($config = NULL) {
			var_dump($config);
		}
}
