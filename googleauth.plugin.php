<?php
class GoogleAuth extends Plugin
{
	private $service = 'Google';
	
	/**
	 * Outputs the "configure" button on the plugin page.
	 */
	public function filter_plugin_config( $actions, $plugin_id ) {
		if ( $plugin_id == $this->plugin_id() ) {
			return array( _t('Configure') );
		}
		return $actions;
	}
	
	/*
	 * Add config
	 */
	public function action_plugin_ui( $plugin_id, $action )
	{
		if ($plugin_id == $this->plugin_id() )
		{
			switch($action)
			{
				case _t('Configure'):
					$form = new FormUI( __CLASS__ );
					$form->append( 'text', 'redirect_uri', __CLASS__ . '__redirect_uri', _t( 'Redirect URI', __CLASS__ ));
					$form->append( 'text', 'client_id', __CLASS__ . '__client_id', _t( 'Client ID', __CLASS__ ));
					$form->append( 'text', 'client_secret', __CLASS__ . '__client_secret', _t( 'Client Secret', __CLASS__ ));
					$form->append( 'text', 'scope', __CLASS__ . '__scope', _t( 'Scope', __CLASS__ ));
					$form->append( 'submit', 'save', _t( 'Save' ) );
					$form->out();
					break;
			}
		}
	}
	
	/*
	 * Add rewrite rule to catch the authentication result
	 */
	public function filter_rewrite_rules($rules)
    {
		$rules[] = RewriteRule::create_url_rule('"oauth2callback"', 'PluginHandler', 'oauth2callback');
        return $rules;
    }
	
	/*
	 * Add Google to the list of social services providing the socialauth feature
	 */
	public function filter_socialauth_services($services = array())
	{
		$services[] = $this->service;
		return $services;
	}
	
	/*
	 * Provide auth link to the theme
	 * @param string $service The service / social network the link is requested for.
	 * @param array Accepts values for overriding the global options redirect_uri and scope and additional state, a value that will be roundtripped through the Google servers until returned with the redirect URI
	 */
	public function theme_socialauth_link($theme, $service, $paramarray = array())
	{
		if($service == $this->service) {
			$opts = Options::get_group( __CLASS__ );
			$url = "https://accounts.google.com/o/oauth2/auth?";
			
			if(isset($paramarray['scope'])) {
				$url .= "scope=" . $paramarray['scope'];
			}
			else {
				$url .= "scope=" . $opts['scope'];
			}
			
			if(isset($paramarray['redirect_uri'])) {
				$url .= "&redirect_uri=" . $paramarray['redirect_uri'];
			}
			else {
				$url .= "&redirect_uri=" . $opts['redirect_uri'];
			}
			
			if(isset($paramarray['state'])) {
				$url .= "&state=" . $paramarray['state'];
			}
			
			$url .= "&response_type=code&client_id=" . $opts['client_id'];
			
			return $url;
		}
	}
	
	/*
	 * Handle the authentication result
	 */
	public function action_plugin_act_oauth2callback($handler)
	{
		$code = $_GET['code'];
		$opts = Options::get_group(__CLASS__);
		
		// Exchange code for token
		$request = new RemoteRequest("https://accounts.google.com/o/oauth2/token", "POST");
		$request->set_postdata(array("code" => $code, "client_id" => $opts['client_id'], "client_secret" => $opts['client_secret'], "redirect_uri" => $opts['redirect_uri'], "grant_type" => "authorization_code"));
		$request->execute();
		
		if ( ! $request->executed() ) {
			throw new XMLRPCException( 16 );
		}
		$json_response = $request->get_response_body();
		$jsondata = json_decode($json_response);
		$token = $jsondata->{'access_token'};
		
		// Offer the token to plugins that want to do something with the authenticated user
		Plugins::act('googleauth_token', $token);
		
		// Get user info. Wrap in try-catch because we don't know if the userinfo is available
		try {
			$request = new RemoteRequest("https://www.googleapis.com/oauth2/v1/userinfo?access_token=$token");
			$request->execute();
			if ( ! $request->executed() ) {
				throw new XMLRPCException( 16 );
			}
			$json_response = $request->get_response_body();
			$jsondata = json_decode($json_response);
			
			// The following is important, because it's part of the "socialauth" feature API
			$userdata = array("id" => $jsondata->id, "name" => $jsondata->name, "email" => $jsondata->email);
			if(isset($jsondata->picture)) {
				$userdata["portrait_url"] = $jsondata->picture;
			}
			if(isset($jsondata->timezone)) {
				$userdata["timezone"] = $jsondata->timezone;
			}
			// Pass the identification data to plugins
			Plugins::act('socialauth_identified', $this->service, $userdata);
		} catch(Exception $e) {
			// don't care if it fails, the only consequence is that action_social_auth will not be triggered, which is correct
		}
	}
}
?>