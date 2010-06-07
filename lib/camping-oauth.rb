=begin rdoc
Author::	Philippe F. Monnet (mailto:pfmonnet@gmail.com)
Copyright:: Copyright (c) 2010 Philippe F. Monnet - OAuth Camping plugin
Copyright:: Copyright (c) 2009 Pelle Braendgaard - A subset of the Rails OAuth plugin reused in  OAuth Camping
License::   Distributes under the same terms as Ruby
Version:: 0.0.1

:main: Camping-OAuth

=Installing Camping-OAuth
A lightweight OAuth plugin for Ruby Camping. 
To install the library and its prerequisisites, type the following commands:

  $ gem install filtering_camping
  $ gem install oauth
  $ gem install oauth-plugin
  $ gem install camping-oauth

=Adding OAuth Provider Support To Your App


===Add new gem and require statements
Add the following statements towards the top of your source file (before the Camping.goes statement):

	gem 'camping' , '>= 2.0'	
	gem 'filtering_camping'
	gem 'oauth'
	gem 'oauth-plugin'

	%w(rubygems active_record camping camping/session markaby json redcloth erb
	oauth
	oauth/server
	oauth/request_proxy
	oauth/request_proxy/rack_request
	filtering_camping
	camping-oauth
	).each { |lib| require lib }

===Customizing the main module

First we'll make sure to include the Camping::Session and CampingFilters modules, and to extend the app module with OAuthCampingPlugin, like so:

	module CampingOAuthProvider
		include Camping::Session
		include CampingFilters
		extend  OAuthCampingPlugin
		include OAuthCampingPlugin::Filters
		
		# ...
	end

This gives us the ability to leverage a logger for the camping-oauth plugin.

OAuthCampingPlugin.logger = Logger.new(File.dirname(__FILE__) + '/yourmodule.log');
OAuthCampingPlugin.logger.level = Logger::DEBUG

Now let's customize the create method by adding a call to OAuthCampingPlugin.create, so we can give the plugin to run any needed initialization.

	def CampingOAuthProvider.create
		OAuthCampingPlugin.create
	end

Ok, at this point we have a minimally configured application module. Our next step is to move on to the Models module.

===Plugging in the OAuth models

First, we'll include the include OAuthCampingPlugin::Models module so we can get all the OAuth-specific models. Then we'll define a User model. The User will need to keep track of the applications it provided access to. It will also manage the tokens associated with these applications. Our model will look like this:

	class User < Base;
		has_many :client_applications
		has_many :tokens, 
			:class_name=>"OauthToken",
			:order=>"authorized_at desc",
			:include=>[:client_application]

	end

Now we need a CreateUserSchema migration class to define our database tables for User, and OAuth models. In the up and down methods we will plugin a call to the corresponding method from the OAuthCampingPlugin::Models module to create the tables for ClientApplication, OAuthToken, and OauthNonce.

	class CreateUserSchema < V 1.0
		def self.up
			create_table :CampingOAuthProvider_users, :force => true do |t|
				t.integer 	:id, :null => false
				t.string		:username
				t.string		:password
			end
			
			User.create :username => 'admin', :password => 'camping'
			
			OAuthCampingPlugin::Models.up
		end
		
		def self.down		
			OAuthCampingPlugin::Models.down
			drop_table :CampingOAuthProvider_users
		end
	end

At this point we can go back to the main module and add the code to configure the ActiveRecord connection and invoke our new schema migration if the User table does not exist yet. This code will be added to the create method:

	module CampingOAuthProvider
		# ...	

		def CampingOAuthProvider.create
			dbconfig = YAML.load(File.read('config/database.yml'))							
			Camping::Models::Base.establish_connection  dbconfig['development']		
			
			OAuthCampingPlugin.create
			
			CampingOAuthProvider::Models.create_schema :assume => (CampingOAuthProvider::Models::User.table_exists? ? 1.1 : 0.0)
		end
	end

You probably noticed that the database configuration is loaded from a database.yml file. So let's create a subfolder named config and a file named database.yml, then let's configure the yaml file as follows:

	development:
	  adapter: sqlite3
	  database: campingoauthprovider.db

Now if we restart the application, our migration should be executed.  
  
===Creating a common helpers module

The Helpers module is used in Camping to provide common utilities to both the Controllers and Views modules. Enhancing our Helpers module is very easy, we need to add both and extend and an include of the OAuthCampingPlugin::Helpers module so we can enhance both instance and class sides:

	module CampingOAuthProvider::Helpers
		extend OAuthCampingPlugin::Helpers
		include OAuthCampingPlugin::Helpers
	end

===E.Plugging in the OAuth controllers

We will need to extend our app Controllers module with the OAuthCampingPlugin::Controllers  module using the extend statement. Then just before the end of the Controllers module, we'll add a call to the include_oauth_controllers  method. This is how camping-oauth will inject and plugin the common OAuth controllers and helpers. It is important that this call always remaining the last statement of the module, even when you add new controller classes. So the module should look like so:

	module CampingOAuthProvider::Controllers
		extend OAuthCampingPlugin::Controllers

		# ...

		include_oauth_controllers
	end #Controllers

Before we continue fleshing out the logic of our controllers, let's finish hooking up the Views module.
			
===Plugging in the OAuth common views

We will need to extend our app Views module with the OAuthCampingPlugin::Views  module using the extend statement. Then just before the end of the Views module, we'll add a call to the include_oauth_views method. This is how camping-oauth will inject and plugin the common OAuth views. It is important that this call always remaining the last statement of the module, even when you add new view methods. So the module should look like so:

	module CampingOAuthProvider::Views
		extend OAuthCampingPlugin::Views

		# ...
		
		include_oauth_views
	end

===Adding basic login and registration capabilities

Let's add a Login controller class to our Controllers module:

	class Login < R '/login'			
		def get
			render :login
		end
		
		def post
			@user = User.find_by_username_and_password(input.username, input.password)

			if @user
				@state.user_id = @user.id

				if @state.return_to.nil?
					redirect R(Index)
				else
					return_to = @state.return_to
					@state.return_to = nil
					redirect(return_to)
				end
			else
				@info = 'Wrong username or password.'
			end
			render :login		
		end
	end

And now add the corresponding login view in the Views module"

	def login
		div @info if @info
		form :action => R(Login), :method => 'post' do
			label 'Username', :for => 'username'; br
			input :name => 'username', :type => 'text'; br

			label 'Password', :for => 'password'; br
			input :name => 'password', :type => 'text'; br

			input :type => 'submit', :name => 'login', :value => 'Login'
		end
	end

Let's verify we can login by accessing the following url: 
	http://localhost:3301/login

Now that login support is in place you can test out one of the OAuth controllers by navigating to the following url:
	http://localhost:3301/oauth/register
	
Since the camping-oauth plugin installed a :before filter on the OAuthRegisterApplication controller requiring user login, you should be redirected first to the login page. Since we created a default account when running the migration, login as admin with camping as the password. Once logged in you should be redirected back to the OAuth Application Registration page.

As a side note, you can style all common OAuth views later using CSS.
We'll let you add the SignUp controller and its signup view on your own.

===Adding our custom API, protected by OAuth

Since the premise of this post was to make it easy for web apps to consume an OAuth-protected service, let's create a very simple controller (no view needed) to expose some data as JSON.

	class APITimeNow < R '/api/timenow'
		def get
			@result = {:now=>Time.now.utc.to_s}
			@result[:username] = @user.username if @user
			
			@headers['Content-Type'] = "application/json"
			log_debug @result.to_json
			@result.to_json
		end
	end

Now we can test it by navigating to the following url (after installing the JSONview plugin for FireFox to make it easier to see the returned JSON data):
		http://localhost:3301/api/timenow
		
Note that at this point this controller is NOT YET protected by OAuth. For that we need to declare a before filter for the APITimeNow controller requiring to be either logged in or OAuth-authenticated. So let's add this code snippet to our main module:

	module GatedCampingSite
		# ...
		
		before [:APITimeNow] do
			login_or_oauth_required
		end
		
		# ...
	end	

So now if we logged out (by deleting the session cookies since we have not implemented logoff) and refreshed our browser we would be redirected to the login page.

==Testing And Troubleshooting

At this stage, we have a basic Camping OAuth provider, now let's test it! The first thing is to register a new OAuth consumer named camping-oauth-consumer. We'll assume that:

   1. it is located at http://localhost:3000/ (fictitious for now)
   2. it exposes a url: http://localhost:3000/callback to accept an OAuth token once authorized

Once you register you should see the a page with the registration results. The key and secret will be used by our consumer as credentials when accessing our OAuth provider, so copy/paste them into a notepad. 

For our first test consumer will use IRB, so open up a session and let's define 3 variables for: url of our provider, key and secret (use your own values) of our registered consumer:

	@site={:site=>"http://localhost:3301"}
	@mykey="SQnIXDQyhFB5q3wfZyMY"
	@mysecret="PmW02FNs7rXG97sAVXMWhFoJVZ98cnj21vv6p1ad"

Now let's require oauth and let's instantiate an OAuth consumer:

	require 'oauth'
	@consumer = OAuth::Consumer.new(@mykey,@mysecret,@site)

You should get an instance of a OAuth::Consumer back. Our next step is to request an OAuth RequestToken like so:

	@request_token = @consumer.get_request_token  

You should get an OAuth::RequestToken back. Let's see how and where we should authorize this request token:
	http://localhost:3301/oauth/authorize?oauth_token=0Qd6g3SjWHQEM6sUTcd9 
	
We should be prompted by the OAuth Authorization controller of our provider. If you click on the checkbox and the Authorize button, the provider will redirect you to the callback url we defined during registration passing back the Oauth token id and and a verifier code. Since we don't have a consumer web app up and running, we will get a navigation error. Here is what the target (redirection) url looks like:
		http://localhost:3000/callback?oauth_token=0Qd6g3SjWHQEM6sUTcd9&oauth_verifier=71Jt3GhiwvHlZYO9zA8c 
		
This verifier acts as a sort of session id we need to pass to get an OAuth Access Token. So from our IRB session, let's evaluate the following statement:

	@verifier = '71Jt3GhiwvHlZYO9zA8c'
	@access_token = @request_token.get_access_token(:oauth_verifier=>@verifier)

You should get an instance of OAuth::AccessToken back. So now let's call our provider api:

	@response = @access_token.get('/api/timenow')
	@info = @response.body

You should get back a JSON object. So this concludes our whirlwind tour of OAuth from a provider and consumer side.

===Examples Source Code
Also if you look in the examples folder of the camping-oauth gem you will find the full source for both a provider (the one we have been working on) and a consumer app (to be run on port 3302).


	
=More information
Check for updates :
- http://blog.monnet-usa.com
=end

require 'oauth'

module OAuth::RequestProxy
  class Base
    alias :original_header_params :header_params

	# Monkey-patched to provide an opportunity to add logging support
    def header_params
		logger = Logger.new(File.dirname(__FILE__) + '/camping-oauth.log')

		begin
		  logger.debug "header_params> request[HTTP_AUTHORIZATION]=#{@request.env['HTTP_AUTHORIZATION']}"
		  hps = original_header_params
		  logger.debug "header_params> result=#{hps.inspect}"
		  hps
		rescue
		  logger.debug "header_params> returning {}"
		  {}
		end
    end
  end
  
  class RackRequest < OAuth::RequestProxy::Base
  protected
	# as of oauth 0.4.0 this method needs to be patched to work with the latest version of Rack
    def request_params	
	  request.POST
    end
  end
end

gem 'oauth-plugin'

require 'activerecord'

# Main module for the OAuth Camping Plugin
#
module OAuthCampingPlugin
	@@logger = nil
	
	# Logger for the OAuthCampingPlugin - can be assigned the main logger for the main web app
	def self.logger
		@@logger
	end

	def self.logger=(a_logger)
		@@logger = a_logger
	end

	# Provides a hook to initialize the plugin in the context of the main web app module
	def self.create
	end		
end

# Helpers module for OAuth Camping Plugin.
# The module will be plugged in to the main app Helpers module. 
# Its methods will be added to Controllers and Views.
# Example:
# 	module CampingOAuthProvider::Helpers
#		extend OAuthCampingPlugin::Helpers
#		include OAuthCampingPlugin::Helpers
#	end 
#
module OAuthCampingPlugin::Helpers
	
	# Logs a specific message if in debug mode
	def log_debug(msg)
		OAuthCampingPlugin.logger.debug(msg)	if OAuthCampingPlugin.logger && OAuthCampingPlugin.logger.debug?
	end

	# Reverse engineers the main app module
	def app_module
		app_module_name = self.class.to_s.split("::").first	
		app_module = app_module_name.constantize	
	end
	
	# Reverse engineers the main User model class
	def user_class
		app_module_name = self.class.to_s.split("::").first	
		user_class_name = "#{app_module_name}::Models::User"	
		user_class_name.constantize
	end
	
	# Reverse engineers the main OauthNonce model class
	def nonce_class
		app_module_name = self.class.to_s.split("::").first	
		nonce_class_name = "#{app_module_name}::Models::OauthNonce"	
		nonce_class_name.constantize
	end
	
 	# Looks up the user based on saved state (if any) and assigns it to the @user variable 
   def set_user
		@user = user_class.find(@state.user_id) if @user.nil? && !@state.nil? && !@state.user_id.nil?
    end	
	
	# Returns the current user model instance
	def current_user
		@user
	end
	
	# Returns whether or not the user is logged in
	# Typically used within a controller before filter such as in:
	#		before :OAuthRegisterApplication do
	#			login_required
	#		end	
    def login_required
		return true if @user
		access_denied
		return false
    end

	# Redirects to the login page with an access denied error message
    def access_denied
		@state.return_to = @request.url
		@info = 'Oops. You need to login before you can view that page.'
		redirect('/login')
    end 	
	
end

# Filters module for OAuth Camping Plugin.
# The module will be plugged in to the main app Helpers module. 
# Example:
#	module CampingOAuthProvider
#		include Camping::Session
#		include CampingFilters
#		extend  OAuthCampingPlugin
#		include OAuthCampingPlugin::Filters
#		
#		# ...
#	end
#
module OAuthCampingPlugin::Filters
	# Adds 3 before filters for the common OAuth controllers:
	#  - OAuthRegisterApplication
	#  - OAuthProvideRequestToken
	#  - OAuthProvideAccessToken
	# Also adds a before filter on all controllers to ensure the user is set
	def self.included(mod)
		mod.module_eval do
			before :all do
				set_user
			end
			
			before :OAuthRegisterApplication do
				login_required
			end		
			
			before :OAuthProvideRequestToken do
				verify_oauth_consumer_signature
			end

			before :OAuthProvideAccessToken do
				verify_oauth_request_token
			end			
		end
	end
end

# OAuth module for OAuth Camping Plugin.
# The module will be plugged into all controllers either: 
#   - directly such as in the standard common OAuth controllers (e.g. OAuthProvideRequestToken)
#   - or indirectly via the include_oauth_controllers of the OAuthCampingPlugin::Controllers module
# The module provides accessors, helper, authentication, signing, and authorization methods specific to OAuth 
#
module OAuthCampingPlugin::OAuth

	protected

	# Returns the current token
	def current_token
		@current_token
	end

	# Returns the current client application
	def current_client_application
		@current_client_application
	end

	# Returns the class of the client application
	def client_application_class
		app_module_name = self.class.to_s.split("::").first	
		client_application_class_name = "#{app_module_name}::Models::ClientApplication"	
		client_application_class_name.constantize
	end
	
	# Returns the class of the current token
	def request_token_class
		app_module_name = self.class.to_s.split("::").first	
		request_token_class_name = "#{app_module_name}::Models::RequestToken"	
		request_token_class_name.constantize
	end
	
	# Returns the class of the access token
	def access_token_class
		app_module_name = self.class.to_s.split("::").first	
		access_token_class_name = "#{app_module_name}::Models::AccessToken"	
		access_token_class_name.constantize
	end
	
	# Parses the HTTP_AUTHORIZATION header for OAuth parameters
	# and returns the params in a hash.
	def oauth_header_params
			oauth_header = @env['HTTP_AUTHORIZATION']
			# parse the header into a Hash
			oauth_params = OAuth::Helper.parse_header(oauth_header)

			# remove non-OAuth parameters
			oauth_params.reject! { |k,v| k !~ /^oauth_/ }
			oauth_params
	end
	
	# Authenticates the current request by verifying the signature in the current token
	# and ensuring that it is an access token
	def oauthenticate
		verified=verify_oauth_signature 
		
		return verified && current_token.is_a?(access_token_class)
	end

	# Returns whether or not the current request is authenticated
	def oauth?
		current_token!=nil
	end
	
	# Returns whether or not the current request is authorized
	def authorized?	# added by @techarch
		return false unless current_token
		current_token.authorized?
	end
	  
	# Ensures that the current controller request is authorized via OAuth.
    # This method is typically used as a precondition in a before_filter.
	# Example:
	#	 before [:APITimeNow] do
	#		login_or_oauth_required
	#	 end	
    def oauth_required
        if oauthenticate
          if authorized?
            return true
          else
            invalid_oauth_response
          end
        else          
          invalid_oauth_response
        end
    end

	# Ensures that the current controller request is authorized either via:
	#  - the application login system
	#  - or via OAuth
    # This method is typically used as a precondition in a before_filter.
	# Example:
	#	 before [:APITimeNow] do
	#		login_or_oauth_required
	#	 end	
    def login_or_oauth_required
        if oauthenticate
			if authorized?
				return true
			else
				invalid_oauth_response
			end
        else
			login_required
        end
    end

    # Verifies that a request token request (signature) is valid for a given consumer clien application
    def verify_oauth_consumer_signature
        begin
			valid = client_application_class.verify_request(request) do |request_proxy|
			@current_client_application = client_application_class.find_by_key(request_proxy.consumer_key)
            # Store this temporarily in client_application object for use in request token generation 
            @current_client_application.token_callback_url=request_proxy.oauth_callback if request_proxy.oauth_callback
            
            # return the token secret and the consumer secret
            [nil, @current_client_application.secret]
          end
        rescue Exception => e
			log_debug e.message  
			log_debug e.backtrace.inspect		
			valid=false
        end

        invalid_oauth_response unless valid
    end
	  
    # Verifies that a request token request (signature) is valid
    def verify_oauth_request_token
        verify_oauth_signature && current_token.is_a?(request_token_class)
    end
	  
	# Returns a 401 HTTP code if  OAuth denied the request
	def invalid_oauth_response(code=401,message="Invalid OAuth Request")
		r(code, {}, message)
	end
	  
    private
      
	# Assigns the current token
    def current_token=(token)
        @current_token=token
        if @current_token
          @current_user=@current_token.user
          @current_client_application=@current_token.client_application 
        end
        @current_token
    end
      
     # Verifies the OAuth signature of the current request
	def verify_oauth_signature
        begin
			valid = client_application_class.verify_request(request) do |request_proxy|
				self.current_token = client_application_class.find_token(request_proxy.token)
			  
	            if self.current_token.respond_to?(:provided_oauth_verifier=)
					self.current_token.provided_oauth_verifier=request_proxy.oauth_verifier 
				end
			
				# return the token secret and the consumer secret
				[(current_token.nil? ? nil : current_token.secret), (current_client_application.nil? ? nil : current_client_application.secret)]
			end
		  
			# reset @current_user to clear state for restful_...._authentication
			@current_user = nil if (!valid)
			valid
        rescue
			false
		end	
	end

end

# Models module for the OAuth Camping Plugin.
# The module will be plugged in to the main app models module. 
# Example:
#	module CampingOAuthProvider::Models
#		include OAuthCampingPlugin::Models
#
#		class User < Base;
#			has_many :client_applications
#			has_many :tokens, :class_name=>"OauthToken",:order=>"authorized_at desc",:include=>[:client_application]
#		
#		end
#		# ...
#	end
#
# This module requires the oauth-plugin gem to be installed as it will load the following models
#   - ClientApplication
#   - OauthToken
#   - OathNonce
#   - RequestToken
#   - AccessToken
#
module OAuthCampingPlugin::Models

	# Loads the 5 standard OAuth models defined in the oauth-plugin gem
	def self.included(mod)
		oauth_plugin_gem = Gem::loaded_specs['oauth-plugin']
		oauth_plugin_path = oauth_plugin_gem.full_gem_path
		provider_template_path = oauth_plugin_path + '/generators/oauth_provider/templates'

		%w(
				client_application.rb
				oauth_token.rb
				oauth_nonce.rb
				request_token.rb
				access_token.rb
		).each { |lib| mod.module_eval(File.read("#{provider_template_path}/#{lib}")) }

		# @techarch : Reset the table names back to pre-Camping
		mod.module_eval do
			mod::ClientApplication.class_eval	{ set_table_name	"client_applications" }
			
			mod::ClientApplication.class_eval	do
				  def self.verify_request(request, options = {}, &block)
					begin
					  signature = OAuth::Signature.build(request, options, &block)
					
						app_module_name = self.to_s.split("::").first	
						nonce_class_name = "#{app_module_name}::Models::OauthNonce"	
						nonce_class = nonce_class_name.constantize

					  return false unless nonce_class.remember(signature.request.nonce, signature.request.timestamp)

					  value = signature.verify
					  value
					rescue OAuth::Signature::UnknownSignatureMethod => e
					  false
					end
				  end
			end

			mod::OauthToken.class_eval 		{ set_table_name	"oauth_tokens" }
			mod::OauthNonce.class_eval 	{ set_table_name	"oauth_nonces" }
		end
	end
	
	# Up-migrates the schema definition for the 5 OAuth models
	def self.up
		ActiveRecord::Schema.define do
			create_table :client_applications do |t|
			  t.string :name
			  t.string :url
			  t.string :support_url
			  t.string :callback_url
			  t.string :key, :limit => 20
			  t.string :secret, :limit => 40
			  t.integer :user_id

			  t.timestamps
			end
			
			add_index :client_applications, :key, :unique
			
			create_table :oauth_tokens do |t|
			  t.integer :user_id
			  t.string :type, :limit => 20
			  t.integer :client_application_id
			  t.string :token, :limit => 20
			  t.string :secret, :limit => 40
			  t.string :callback_url
			  t.string :verifier, :limit => 20
			  t.timestamp :authorized_at, :invalidated_at
			  t.timestamps
			end
			
			add_index :oauth_tokens, :token, :unique
			
			create_table :oauth_nonces do |t|
			  t.string :nonce
			  t.integer :timestamp

			  t.timestamps
			end
			
			add_index :oauth_nonces,[:nonce, :timestamp], :unique		
		
		end
	end

	# Down-migrates the schema definition for the 5 OAuth models
	def self.down
		ActiveRecord::Schema.define do
			drop_table :client_applications
			drop_table :oauth_tokens
			drop_table :oauth_nonces
		end
	end

end

# Controllers module for the OAuth Camping Plugin.
# The module will be plugged in to the main app controllers module using:
#	 - extend to add class methods to the app controllers module
#	-  include_oauth_controllers to dynamically plugin the OAuth and Helpers modules inside each controller class
#		(this is why the call must be the last statement in the controllers module)
#
# Example:
#  module CampingOAuthProvider::Controllers
#		extend OAuthCampingPlugin::Controllers
#
#		# ...
#
#		include_oauth_controllers
#  end
#
module OAuthCampingPlugin::Controllers

	# Returns the source code for all common OAuth controllers
	def self.common_oauth_controllers
		<<-CLASS_DEFS
			
	class OAuthRegisterApplication < R '/oauth/register'
		def get
			@application= ClientApplication.new
			render :new_application_registration
		end
		
		def post
			@user = User.find(@state.user_id)
			if !@user
				return "login first"
			end

			@application = ClientApplication.find_by_user_id_and_name(@state.user_id, input.name)
			if @application
				@info = 'You already have an application with this name.'
			else
				@application = ClientApplication.new :user_id => @state.user_id,
					:name => input.name,
					:url => input.url,
					:support_url => input.support_url,
					:callback_url => input.callback_url
					
				@user.client_applications << @application

				@application.save
				if @application
					return(render(:application_registration))
				else
					@info = @application.errors.full_messages unless @application.errors.empty?
				end
			end
			
			render :new_application_registration
		end
	end
	
	class OAuthProvideRequestToken < R '/oauth/request_token'
		include OAuthCampingPlugin::OAuth
	
		def post
			oauth_consumer_key = oauth_header_params['oauth_consumer_key']

			@application = ClientApplication.find_by_key(oauth_consumer_key)
			@token = @application.create_request_token
			log_debug 'OAuthProvideRequestToken> request token for oauth_consumer_key:' + oauth_consumer_key + '=' + @token.inspect
			@token.to_query
		end
	end
	
	class OAuthAuthorizeToken < R '/oauth/authorize'
		include OAuthCampingPlugin::OAuth
	
		def get
			@oauth_token = input.oauth_token
			render :authorize
		end
		
		def post
			@token = RequestToken.find_by_token input.oauth_token
			return(render(:authorize_failure_token_not_found)) if @token.nil?
			
			return(render(:authorize_failure_invalidated)) if @token.invalidated? 
			
 			return(render(:authorize_failure)) unless user_authorizes_token?

            @token.authorize!(current_user)
			log_debug 'OAuthAuthorizeToken> request token=' + @token.inspect
			
            if @token.oauth10?
                @redirect_url = input.oauth_callback || @token.client_application.callback_url
            else
                @redirect_url = (@token.oob? || @token.callback_url.nil?) ? @token.client_application.callback_url : @token.callback_url
            end
	
 			return(render(:authorize_success)) unless @redirect_url

			@full_redirect_url = @token.oauth10? ? (@redirect_url + '?oauth_token=' + @token.token) :  (@redirect_url + '?oauth_token=' + @token.token + '&oauth_verifier=' + @token.verifier)
			
			redirect @full_redirect_url
		end
		
		# Override this to match your authorization page form
		def user_authorizes_token?
			input.authorize == '1' || input.authorize == 'on'
		end		
	end
	
	class OAuthRevokeToken < R '/oauth/revoke'
		include OAuthCampingPlugin::OAuth
	
		def get
			@token = OauthToken.find_by_token(input.oauth_token)
			return(render(:authorize_failure_token_not_found)) if @token.nil?

			render :revoke
		end
		
		def post
			@token = OauthToken.find_by_token(input.oauth_token)
			return(render(:authorize_failure_token_not_found)) if @token.nil?

			if input.revoke != 'on'
				@info = "You did not confirm you wanted to revoke this token. Check the checkbox to confirm."
				return(render(:revoke))
			end
			
			@token.invalidate!
			log_debug 'OAuthRevokeToken> access token=' + @token.inspect
			
			render :revoke_success
		end
	end
	
	class OAuthProvideAccessToken < R '/oauth/access_token'
		include OAuthCampingPlugin::OAuth
	
		def post
			log_debug 'OAuthProvideAccessToken> @current_token=' + self.current_token.inspect

			return(r(401,'')) if self.current_token.nil?
			
			@token = self.current_token.exchange!
			log_debug 'OAuthProvideAccessToken> access token=' + @token.inspect

			return(r(401,'')) if self.current_token.nil?
			@token.to_query
			
		end #post
 	end
	
		CLASS_DEFS
	end
	
	# Includes the OAuth and Helpers modules inside each controller class using class_eval
	# (this is why the call must be the last statement in the controllers module)
	def include_oauth_controllers
		module_eval OAuthCampingPlugin::Controllers.common_oauth_controllers

		# Add Oauth to each controller
		r.each do |x| 
			x.class_eval do
				include OAuthCampingPlugin::OAuth
				include OAuthCampingPlugin::Helpers
			end
		end			
	end
end

# Views module for the OAuth Camping Plugin.
# The module will be plugged in to the main app views module using:
#	 - extend to add class methods to the app views module
#	-  include_oauth_views to dynamically plugin the common OAuth views (e.g. authorize_view) 
#
# Example:
#  module CampingOAuthProvider::Views
#		extend OAuthCampingPlugin::Views
#
#		# ...
#
#		include_oauth_views
#  end
#
module OAuthCampingPlugin::Views

	# Returns the source code for all common OAuth views such as error views (e.g. authorize_failure)
	def self.common_oauth_views
		<<-VIEW_DEFS
		
	def authorize_failure
		h1 "You have denied access to this token"
	end
	
	def authorize_failure_token_not_found
		h1 "Token not found"
	end
	
	def authorize_failure_invalidated
		h1 "Token could not be authorized since it has become invalid"
	end		
	
	def authorize_success
		h1 "You have successfully authorized access to this token"
		p @info
	end	
	
	def revoke_success
		h1 "You have successfully revoked access to this token"
		p @info
	end	
		VIEW_DEFS
	end

	# Returns the source code for the register_view
	def self.register_view
		<<-VIEW

	def new_application_registration
		h2 "New OAuth Consumer"
		h3 "Application Registration"
		div.info @info if @info
		form.new_app_reg! :action => R(OAuthRegisterApplication), :method => 'post' do
			label 'Name (*)', :for => 'name'; br
			input.app_name! :name => 'name', :type => 'text'; br

			label 'Url (*)', :for => 'url'; br
			input.url :name => 'url', :type => 'text'; br

			label 'Callback Url (*)', :for => 'callback_url'; br
			input.url :name => 'callback_url', :type => 'text'; br;

			label 'Support Url', :for => 'support_url'; br
			input.url :name => 'support_url', :type => 'text'; br;br;

			input :type => 'submit', :name => 'signup', :value => 'Register'
		end
	end		
	
		VIEW
	end

	# Returns the source code for the registration_view
	def self.registration_view
		<<-VIEW

	def application_registration
		h2 "Application Registration"
		div @info if @info
		
		table.application_registration do
			tr { td "Name"; 			td @application.name}
			tr { td "Url"; 					td @application.url}
			tr { td "Support Url";		td @application.support_url}
			tr { td "Callback Url";	td @application.callback_url}
			tr { td "Key"; 				td @application.key}
			tr { td "Secret"; 			td @application.secret}
		end		
	end		
	
		VIEW
	end
	
	# Returns the source code for the authorize_view
	def self.authorize_view
		<<-VIEW
		
	def authorize
		div @info if @info
		form :action => R(OAuthAuthorizeToken), :method => 'post' do
			input :name => 'oauth_token', :type=>'hidden', :value=>@oauth_token;
			input :name => 'authorize', :type=>'checkbox';
			label 'Authorize token ' + @oauth_token, :for => 'authorize'; br
			
			input :type => 'submit', :name => 'authorize_btn', :value => 'Authorize'
			a "Cancel", :href=>"/applications"
		end
	end

		VIEW
	end

	# Returns the source code for the revoke_view
	def self.revoke_view
		<<-VIEW
		
	def revoke
		div @info if @info
		form :action => R(OAuthRevokeToken), :method => 'post' do
			input :name => 'oauth_token', :type=>'hidden', :value=>@token.token;
			input :name => 'revoke', :type=>'checkbox';
			label 'Revoke token ' + @token.token, :for => 'revoke'; br
			
			input :type => 'submit', :name => 'revoke_btn', :value => 'Revoke'
			a "Cancel", :href=>"/applications"
		end
	end

		VIEW
	end
	
	# Includes all common OAuth views inside the views module using module_eval
	# (this is why the call must be the last statement in the views module)
	def include_oauth_views
		module_eval OAuthCampingPlugin::Views.common_oauth_views
		
		module_eval do
			app_module_name = self.to_s.split("::").first	
			mab_class_name = "#{app_module_name}::Mab"	
			mab_class = mab_class_name.constantize

			unless mab_class.public_instance_methods.include? 'register' 
				module_eval OAuthCampingPlugin::Views.register_view
			end

			unless mab_class.public_instance_methods.include? 'application_registration' 
				module_eval OAuthCampingPlugin::Views.registration_view
			end
			
			unless mab_class.public_instance_methods.include? 'authorize' 
				module_eval OAuthCampingPlugin::Views.authorize_view
			end
			
			unless mab_class.public_instance_methods.include? 'revoke' 
				module_eval OAuthCampingPlugin::Views.revoke_view
			end
		end
		
	end
end
