gem 'camping' , '>= 2.0'	
gem 'RedCloth'						
gem 'filtering_camping'
gem 'oauth', '>= 0.3.6' # '0.4.0' #
gem 'oauth-plugin'

%w(rubygems active_record camping camping/session markaby json redcloth erb
oauth
oauth/server
oauth/request_proxy
oauth/request_proxy/rack_request
filtering_camping
camping-oauth
).each { |lib| require lib }

Camping.goes :CampingOAuthProvider

module CampingOAuthProvider
	include Camping::Session
	include CampingFilters
	extend  OAuthCampingPlugin
	include OAuthCampingPlugin::Filters

	OAuthCampingPlugin.logger = Logger.new(File.dirname(__FILE__) + '/camping-oauth-provider.log');
	OAuthCampingPlugin.logger.level = Logger::DEBUG

	before [:ViewApplications, :ViewTokens] do
		login_required 
	end
	
	before [:Index] do
	end
	
	before [:APITimeNow] do
		login_or_oauth_required
	end	

	def CampingOAuthProvider.create
		dbconfig = YAML.load(File.read('config/database.yml'))								
		Camping::Models::Base.establish_connection  dbconfig['development']	
		
		OAuthCampingPlugin.create
		
		CampingOAuthProvider::Models.create_schema :assume => (CampingOAuthProvider::Models::User.table_exists? ? 1.1 : 0.0)
	end
end

module CampingOAuthProvider::Models
	include OAuthCampingPlugin::Models

	class User < Base;
		has_many :client_applications
		has_many :tokens, :class_name=>"OauthToken",:order=>"authorized_at desc",:include=>[:client_application]
	
	end

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

end

module CampingOAuthProvider::Helpers
	extend OAuthCampingPlugin::Helpers
	include OAuthCampingPlugin::Helpers
end

module CampingOAuthProvider::Controllers
	extend OAuthCampingPlugin::Controllers

	class Index
		def get 
			render :index
		end
	end

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
		
	class APITimeNow < R '/api/timenow'
		def get
			@result = {:now=>Time.now.utc.to_s}
			@result[:username] = @user.username if @user
			
			@headers['Content-Type'] = "application/json"
			log_debug @result.to_json
			@result.to_json
		end
	end
	
	include_oauth_controllers
end #Controllers

module CampingOAuthProvider::Views
	extend OAuthCampingPlugin::Views

	def index
		h1 'My CampingOAuthProvider App'
		div 'To be continued ...'
	end
	
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
	
	include_oauth_views
end

CampingOAuthProvider.create
