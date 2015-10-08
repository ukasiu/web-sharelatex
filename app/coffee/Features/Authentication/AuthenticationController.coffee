AuthenticationManager = require ("./AuthenticationManager")
LoginRateLimiter = require("../Security/LoginRateLimiter")
UserGetter = require "../User/UserGetter"
UserUpdater = require "../User/UserUpdater"
UserCreator = require("../User/UserCreator")
Metrics = require('../../infrastructure/Metrics')
logger = require("logger-sharelatex")
querystring = require('querystring')
Url = require("url")
Settings = require "settings-sharelatex"
basicAuth = require('basic-auth-connect')
OAuth = require('oauth');
oauth2 = new OAuth.OAuth2('1aa61d56be9d1d09d948ffccfe09856d361ccd1b571917f0e274282200170136',
	'b4f6db0d838e3b6053a68fdfe0ee7a3d20313f8e183562a88a9983fca6c01398', 
	'https://accounts.iiet.pl/', 
	'oauth/authorize',
	'oauth/token', 
	null);

module.exports = AuthenticationController =
	oauth_login: (req, res, next = (error) ->) ->
		url = oauth2.getAuthorizeUrl
		  redirect_uri: 'http://localhost:3000/oauth_callback'
		  scope: 'public extended'
		  response_type: 'code'
		  state: 'test' # TODO save in session data
		res.redirect url

	oauth_callback: (req, res, next = (error) ->) ->
		oauth2.getOAuthAccessToken req.query.code, 
			grant_type: 'authorization_code'
			redirect_uri: 'http://localhost:3000/oauth_callback',
			(e, access_token, refresh_token, results) ->
			  oauth2.getProtectedResource 'https://accounts.iiet.pl/oauth/v1/extended', access_token, (a,user_data,c,sth) ->
			  	user_data = JSON.parse(user_data)
			  	redir = Url.parse(req.body?.redir or "/project").path
			  	AuthenticationManager.authenticateOAuth oauth_id: user_data.user_id, user_data.oauth_id, (error, user) ->
			  		return next(error) if error?
			  		if user?
			  			AuthenticationController._recordSuccessfulLogin user._id
			  			AuthenticationController.establishUserSession req, user, (error) ->
			  				return next(error) if error?
			  				req.session.justLoggedIn = true
			  				logger.log user_id: user._id.toString(), "successful log in"
			  				res.redirect redir
			  		else
			  			UserCreator.createNewUser 
			  				holdingAccount: false
			  				email: user_data.login + "@iiet.pl"
			  				oauth_id: user_data.user_id,
			  				(err, user) ->
			  					return next(error) if error?
			  					if user?
			  						AuthenticationController._recordSuccessfulLogin user._id
			  						AuthenticationController.establishUserSession req, user, (error) ->
			  							return next(error) if error?
			  							req.session.justLoggedIn = true
			  							logger.log user_id: user._id.toString(), "successful log in"
			  							res.redirect redir

	login: (req, res, next = (error) ->) ->
		email = req.body?.email?.toLowerCase()
		password = req.body?.password
		redir = Url.parse(req.body?.redir or "/project").path
		LoginRateLimiter.processLoginRequest email, (err, isAllowed)->
			if !isAllowed
				logger.log email:email, "too many login requests"
				res.statusCode = 429
				return res.send
					message:
						text: req.i18n.translate("to_many_login_requests_2_mins"),
						type: 'error'
			AuthenticationManager.authenticate email: email, password, (error, user) ->
				return next(error) if error?
				if user?
					LoginRateLimiter.recordSuccessfulLogin email
					AuthenticationController._recordSuccessfulLogin user._id
					AuthenticationController.establishUserSession req, user, (error) ->
						return next(error) if error?
						req.session.justLoggedIn = true
						logger.log email: email, user_id: user._id.toString(), "successful log in"
						res.send redir: redir
				else
					AuthenticationController._recordFailedLogin()
					logger.log email: email, "failed log in"
					res.send message:
						text: req.i18n.translate("email_or_password_wrong_try_again"),
						type: 'error'

	getAuthToken: (req, res, next = (error) ->) ->
		AuthenticationController.getLoggedInUserId req, (error, user_id) ->
			return next(error) if error?
			AuthenticationManager.getAuthToken user_id, (error, auth_token) ->
				return next(error) if error?
				res.send(auth_token)

	getLoggedInUserId: (req, callback = (error, user_id) ->) ->
		if req?.session?.user?._id?
			callback null, req.session.user._id.toString()
		else
			callback null, null

	getLoggedInUser: (req, options = {allow_auth_token: false}, callback = (error, user) ->) ->
		if typeof(options) == "function"
			callback = options
			options = {allow_auth_token: false}

		if req.session?.user?._id?
			query = req.session.user._id
		else if req.query?.auth_token? and options.allow_auth_token
			query = { auth_token: req.query.auth_token }
		else
			return callback null, null

		UserGetter.getUser query, callback

	requireLogin: (options = {allow_auth_token: false, load_from_db: false}) ->
		doRequest = (req, res, next = (error) ->) ->
			load_from_db = options.load_from_db
			if req.query?.auth_token? and options.allow_auth_token
				load_from_db = true
			if load_from_db
				AuthenticationController.getLoggedInUser req, { allow_auth_token: options.allow_auth_token }, (error, user) ->
					return next(error) if error?
					return AuthenticationController._redirectToLoginOrRegisterPage(req, res) if !user?
					req.user = user
					return next()
			else
				if !req.session.user?
					AuthenticationController._redirectToLoginOrRegisterPage(req, res) 
				else
					req.user = req.session.user
					return next()

		return doRequest

	_globalLoginWhitelist: []
	addEndpointToLoginWhitelist: (endpoint) ->
		AuthenticationController._globalLoginWhitelist.push endpoint

	requireGlobalLogin: (req, res, next) ->
		if req._parsedUrl.pathname in AuthenticationController._globalLoginWhitelist
			return next()

		if req.headers['authorization']?
			return AuthenticationController.httpAuth(req, res, next)
		else if req.session.user?
			return next()
		else
			logger.log url:req.url, "user trying to access endpoint not in global whitelist"
			return res.redirect "/login"

	httpAuth: basicAuth (user, pass)->
		isValid = Settings.httpAuthUsers[user] == pass
		if !isValid
			logger.err user:user, pass:pass, "invalid login details"
		return isValid

	_redirectToLoginOrRegisterPage: (req, res)->
		if req.query.zipUrl? or req.query.project_name?
			return AuthenticationController._redirectToRegisterPage(req, res) 
		else
			AuthenticationController._redirectToLoginPage(req, res) 


	_redirectToLoginPage: (req, res) ->
		logger.log url: req.url, "user not logged in so redirecting to login page"
		req.query.redir = req.path
		url = "/login?#{querystring.stringify(req.query)}"
		res.redirect url
		Metrics.inc "security.login-redirect"

	_redirectToRegisterPage: (req, res) ->
		logger.log url: req.url, "user not logged in so redirecting to register page"
		req.query.redir = req.path
		url = "/register?#{querystring.stringify(req.query)}"
		res.redirect url
		Metrics.inc "security.login-redirect"

	_recordSuccessfulLogin: (user_id, callback = (error) ->) ->
		UserUpdater.updateUser user_id.toString(), {
			$set: { "lastLoggedIn": new Date() },
			$inc: { "loginCount": 1 }
		}, (error) ->
			callback(error) if error?
			Metrics.inc "user.login.success"
			callback()

	_recordFailedLogin: (callback = (error) ->) ->
		Metrics.inc "user.login.failed"
		callback()

	establishUserSession: (req, user, callback = (error) ->) ->
		lightUser =
			_id: user._id
			first_name: user.first_name
			last_name: user.last_name
			isAdmin: user.isAdmin
			email: user.email
			referal_id: user.referal_id
		# Regenerate the session to get a new sessionID (cookie value) to
		# protect against session fixation attacks
		oldSession = req.session
		req.session.destroy()
		req.sessionStore.generate(req)
		for key, value of oldSession
			req.session[key] = value

		req.session.user = lightUser
		callback()
