gem 'camping' , '>= 2.0'	# @techarch : updated version
gem 'RedCloth'						# @techarch : added since it is referenced in the Posts model
gem 'oauth'

%w(
rubygems
active_record
camping
camping/session
markaby
json
redcloth
oauth
).each { |lib| require lib }

Camping.goes :CampingOAuthConsumer

CampingOAuthProvider_URL = "http://localhost:3301/"
CampingOAuthProvider_KEY = "SQnIXDQyhFB5q3wfZyMY"	# REPLACE WITH THE KEY OBTAINED THROUGH REGISTRATION
CampingOAuthProvider_SECRET = "PmW02FNs7rXG97sAVXMWhFoJVZ98cnj21vv6p1ad"	# REPLACE WITH THE SECRET OBTAINED THROUGH REGISTRATION

module CampingOAuthConsumer
	include Camping::Session
	
	def CampingOAuthConsumer.create
		Camping::Models::Base.logger = Logger.new(File.dirname(__FILE__) + '/camping-oauth-consumer.log')
		Camping::Models::Base.logger.level = Logger::DEBUG
	end
end

module CampingOAuthConsumer::Controllers
	class Index < R '/'
		def get
			render :index
		end
	end
	
	class RequestToken < R '/token/request'
		def get
			@consumer = OAuth::Consumer.new(CampingOAuthProvider_KEY,CampingOAuthProvider_SECRET, {:site => CampingOAuthProvider_URL})
			return(render(:invalid_key_and_secret)) unless @consumer
			
			@token = @consumer.get_request_token
			@state.token = @token.to_yaml
			
			render :index
		end
	end
	
	class AuthorizeToken < R '/token/authorize'
		def get
			if @state.nil? || @state.token.nil?
				@info = "A token has not yet been requested"
				return(render (:index))
			end
			
			@token = YAML::load @state.token
			redirect @token.authorize_url.gsub("//oauth","/oauth")
		end
	end
	
	class AccessTokenAuthorized < R '/callback'
		def get
			@state.oauth_verifier = input.oauth_verifier
			@info = "Token has been successfully authorized with oauth verifier: #{input.oauth_verifier}"
			render :index
		end
	end
	
	class AccessToken < R '/token/access'
		def get
			if @state.nil? || @state.token.nil? 
				@info = "A token has not yet been requested"
				return(render (:index))
			end
			
			if @state.oauth_verifier.nil? 
				@info = "A token has not yet been authorized (missing the OAuth Verifier)"
				return(render (:index))
			end

			@token = YAML::load @state.token
			@token = @token.get_access_token(:oauth_verifier=>@state.oauth_verifier)
			@state.token = @token.to_yaml
			
			render :index
		end
	end
	
	class GetTimeNow < R '/get-time-now'
		def get
			if @state.nil? || @state.token.nil? 
				@info = "A request/access token has not yet been requested"
				return(render (:index))
			end
			
			@token = YAML::load @state.token
puts "GetTimeNow> access token=#{@token.inspect}"			
			response = @token.get('/api/timenow')
			@info = response.body
			
			render :time_now
		end
	end
	
end

module CampingOAuthConsumer::Views

	def layout
		html do
		
			head do
				title "CampingOAuthConsumer (Ruby Camping OAuth Consumer Demo)"
				
				style  :type => 'text/css' do
<<-STYLE				
body {
	padding:0 0 0 0;
	margin:0;
	font-family:'Lucida Grande','Lucida Sans Unicode',sans-serif;
	font-size: 0.8em;
	color:#303030;
	background-color: #d7e7ed;
}

a {
	color:#303030;
	text-decoration:none;
	border-bottom:1px dotted #505050;
}

a:hover {
	color:#303030;
	background: yellow;
	text-decoration:none;
	border-bottom:4px solid orange;
}

h1 {
	font-size: 14px;
	color: blue;
}

table {
	font-size:0.9em;
	width: 1050px;
	}

tr 
{
	background:lightgoldenRodYellow;
	vertical-align:top;
}

th
{
	font-size: 0.9em;
	font-weight:bold;
	background:lightBlue none repeat scroll 0 0;
	
	text-align:left;	
}
	
STYLE
				end
			end #head
		
		  body do
			div "CampingOAuthConsumer (Ruby Camping OAuth Consumer Demo)"
			hr
			
			self << yield
			
			br
			a "Home", :href=>"/"
			div.footer! do
				hr
				span.copyright_notice! { "Copyright &copy; 2010 &nbsp; -  #{ a('Philippe Monnet (@techarch)', :href => 'http://blog.monnet-usa.com/') }  " }
			end
		  end

		end
	end

	def index
		h1 "CampingOAuthConsumer"
		div @info if @info
		ul do
			if @state.nil?
				li { a "Login", :href=>'/login'}
				li { a "Sign-Up", :href=>'/signup'}
			else
				li { a "Request Token from CampingOAuthProvider", 		:href=>'/token/request'}
				li { a "AuthorizeToken at CampingOAuthProvider", 			:href=>'/token/authorize'}
				li { a "Get Access Token from CampingOAuthProvider",	:href=>'/token/access'}
				li { a "Get Time Now from CampingOAuthProvider", 		:href=>'/get-time-now'}
			end
		end
		
		if @state.token
			hr
			div "Token=#{@state.token}"
		end
		
		if @state.oauth_verifier
			hr
			div "OAuth Verifier=#{@state.oauth_verifier}"
		end
		
	end

	def invalid_key_and_secret
		h1 "Invalid key and secret for CampingOAuthProvider"
	end
	
	def time_now
		h1 "Time Now"
		div @info if @info
	end
end

CampingOAuthConsumer.create
