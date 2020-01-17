const os = require('os');
const path = require('path');
const axios = require('axios');
const jsonfile = require('jsonfile');
const httpStatus = require('http-status');
const TypeUtils = require('data-type-utils');
const packageJson = require('./package.json');

const log4js = require('@log4js-node/log4js-api');

class EsdrRequestError extends Error {
   constructor(axiosError) {
      super();

      if (Error.captureStackTrace) {
         Error.captureStackTrace(this, EsdrRequestError);
      }

      this.message = axiosError.message;
      this.config = axiosError.config;
      this.response = axiosError.response;
   }
}

class EsdrEntityExistsError extends EsdrRequestError {
   constructor(axiosError) {
      super(axiosError);

      if (Error.captureStackTrace) {
         Error.captureStackTrace(this, EsdrEntityExistsError);
      }
   }
}

class EsdrNoResponseError extends Error {
   constructor(axiosError) {
      super();

      if (Error.captureStackTrace) {
         Error.captureStackTrace(this, EsdrNoResponseError);
      }

      this.message = axiosError.message;
      this.config = axiosError.config;
      this.request = axiosError.request;
   }
}

class EsdrUnexpectedError extends Error {
   constructor(axiosError) {
      super();

      if (Error.captureStackTrace) {
         Error.captureStackTrace(this, EsdrUnexpectedError);
      }

      this.message = axiosError.message;
      this.config = axiosError.config;
   }
}

const convertAxiosErrorToEsdrError = function(axiosError) {
   if (axiosError.response) {
      if (axiosError.response.status === httpStatus.CONFLICT) {
         return new EsdrEntityExistsError(axiosError)
      }
      return new EsdrRequestError(axiosError);
   }
   else if (axiosError.request) {
      return new EsdrNoResponseError(axiosError);
   }

   return new EsdrUnexpectedError(axiosError);
};

/**
 * A strategy for storing OAuth2 tokens.
 *
 * @abstract
 */
class TokenStorageStrategy {
   constructor() {
      if (new.target === TokenStorageStrategy) {
         throw new TypeError("Cannot construct TokenStorageStrategy instances directly");
      }
   }

   /**
    * Returns true if the given arguments are valid.  Throws a TypeError otherwise.
    *
    * @param {!int} userId The user ID.  Must be an positive integer and non-null.
    * @param {!string} accessToken The OAuth2 access token.  Must be a non-empty string and non-null.
    * @param {!string} refreshToken The OAuth2 refresh token.  Must be a non-empty string and non-null.
    * @returns {boolean}
    */
   _isValid(userId, accessToken, refreshToken) {
      if (!TypeUtils.isPositiveInt(userId)) {
         throw new TypeError("userId must be a positive integer");
      }
      if (!TypeUtils.isNonEmptyString(accessToken)) {
         throw new TypeError("accessToken must be a non-empty string");
      }
      if (!TypeUtils.isNonEmptyString(refreshToken)) {
         throw new TypeError("refreshToken must be a non-empty string");
      }

      return true;
   }

   /**
    * Attempts to load the tokens.  Returns a boolean indicating whether the load was successful.
    *
    * @returns {Promise<boolean>}
    */
   async load() {
      throw new TypeError("Must implement method load()");
   }

   /**
    * Persists the OAuth2 user ID, access token, and refresh token.
    *
    * @param {!int} userId The user ID.  Must be an positive integer and non-null.
    * @param {!string} accessToken The OAuth2 access token.  Must be a non-empty string and non-null.
    * @param {!string} refreshToken The OAuth2 refresh token.  Must be a non-empty string and non-null.
    * @returns {Promise<boolean>}
    * @throws TypeError
    * @abstract
    */
   async save(userId, accessToken, refreshToken) {
      throw new TypeError("Must implement method save()");
   }

   /**
    * Returns the user ID, or null if it hasn't been saved yet.
    *
    * @returns {?int} The user ID.  May be null if it hasn't been saved yet.
    * @abstract
    */
   getUserId() {
      throw new TypeError("Must implement getUserId()");
   }

   /**
    * Returns the access token, or null if it hasn't been saved yet.
    *
    * @returns {?string} The access token.  May be null if it hasn't been saved yet.
    * @abstract
    */
   getAccessToken() {
      throw new TypeError("Must implement getAccessToken()");
   }

   /**
    * Returns the refresh token, or null if it hasn't been saved yet.
    *
    * @returns {?string} The refresh token.  May be null if it hasn't been saved yet.
    * @abstract
    */
   getRefreshToken() {
      throw new TypeError("Must implement getRefreshToken()");
   }

   /**
    * Returns a boolean indicating whether the tokens have been loaded/set yet
    *
    * @returns {boolean}
    */
   hasTokens() {
      // noinspection JSIncompatibleTypesComparison
      return this.getUserId() !== null &&
             this.getAccessToken() !== null &&
             this.getRefreshToken() !== null;
   }
}

class InMemoryTokenStorageStrategy extends TokenStorageStrategy {
   constructor() {
      super();

      this._userId = null;
      this._accessToken = null;
      this._refreshToken = null;
   }

   getUserId() {
      return this._userId;
   }

   getAccessToken() {
      return this._accessToken;
   }

   getRefreshToken() {
      return this._refreshToken;
   }

   async load() {
      return this.hasTokens();
   }

   async save(userId, accessToken, refreshToken) {
      if (this._isValid(userId, accessToken, refreshToken)) {
         this._userId = userId;
         this._accessToken = accessToken;
         this._refreshToken = refreshToken;
         return true;
      }
      return false;
   }
}

class JsonFileTokenStorageStrategy extends TokenStorageStrategy {
   constructor(jsonFilePath) {
      super();
      this._authFile = path.resolve(__dirname, jsonFilePath);
      this._log = log4js.getLogger('JsonFileTokenStorageStrategy');
      this._tokens = new InMemoryTokenStorageStrategy();
   }

   getUserId() {
      return this._tokens.getUserId();
   }

   getAccessToken() {
      return this._tokens.getAccessToken();
   }

   getRefreshToken() {
      return this._tokens.getRefreshToken();
   }

   async load() {
      this._log.debug("Reading auth file [" + this._authFile + "]");
      let auth = {
         userId : null,
         accessToken : null,
         refreshToken : null
      };
      try {
         auth = jsonfile.readFileSync(this._authFile);

         // update the in-memory store
         return await this._tokens.save(auth.userId, auth.accessToken, auth.refreshToken);
      }
      catch (err) {
         this._log.warn("Error reading auth file: ", err.message);
      }
      return false;
   }

   async save(userId, accessToken, refreshToken) {
      if (this._isValid(userId, accessToken, refreshToken)) {
         try {
            jsonfile.writeFileSync(this._authFile,
                                   {
                                      userId : userId,
                                      accessToken : accessToken,
                                      refreshToken : refreshToken
                                   },
                                   { spaces : 3 });

            // update the in-memory store
            return await this._tokens.save(userId, accessToken, refreshToken)
         }
         catch (e) {
            this._log.error("Failed to persist authorization to file [" + this._authFile + "]", e);
         }
      }
      return false;
   }
}

// TODO: make this configurable
const HTTP_TIMEOUT_MILLIS = 10000;

class EsdrClient {
   constructor(host, userCredentials, oAuth2ClientCredentials, tokenPersistenceStrategy, appName) {
      if (!TypeUtils.isNonEmptyString(host)) {
         throw new TypeError("host must be a non-empty string");
      }
      if (!TypeUtils.isDefinedAndNotNull(userCredentials)) {
         throw new TypeError("userCredentials must be defined and non-null");
      }
      if (!TypeUtils.isDefinedAndNotNull(oAuth2ClientCredentials)) {
         throw new TypeError("oAuth2ClientCredentials must be defined and non-null");
      }
      if (!TypeUtils.isNonEmptyString(appName)) {
         throw new TypeError("appName must be a non-empty string");
      }
      if (!(tokenPersistenceStrategy instanceof TokenStorageStrategy)) {
         throw new TypeError("tokenPersistenceStrategy must be an instance of a class which implements the TokenStorageStrategy abstract class");
      }

      this._log = log4js.getLogger('EsdrClient[' + appName + ']');

      const userAgent = [
         appName + '[EsdrClient]/' + packageJson.version,
         '(' + os.type() + ' ' + os.arch() + '; ' + os.release() + ')',
         'Node.js/' + process.version,
         'Axios/' + packageJson.dependencies.axios
      ].join(' ');
      this._axios = axios.create({
                                    baseURL : 'https://' + host,
                                    timeout : HTTP_TIMEOUT_MILLIS,
                                    headers : { 'user-agent' : userAgent }
                                 });

      this._user = {
         username : userCredentials['username'],
         password : userCredentials['password']
      };
      this._client = {
         id : oAuth2ClientCredentials['id'],
         secret : oAuth2ClientCredentials['secret']
      };

      this._tokenStore = tokenPersistenceStrategy;
   }

   async _callEsdr(url, method, data, willIncludeAuthorization = false) {
      const self = this;
      const doRequest = async function() {
         try {
            const requestConfig = {
               url : url,
               method : method,
               data : data,
               headers : {}
            };
            if (willIncludeAuthorization) {
               requestConfig['headers']['Authorization'] = 'Bearer ' + self._tokenStore.getAccessToken();
            }
            return await self._axios(requestConfig);
         }
         catch (err) {
            self._log.error("Error in request to [" + url + "]: ", err.message);
            throw convertAxiosErrorToEsdrError(err);
         }
      };

      try {
         if (willIncludeAuthorization) {
            await self._ensureTokensAreLoaded();
         }
         return await doRequest();
      }
      catch (err) {
         if (willIncludeAuthorization &&
             err instanceof EsdrRequestError &&
             err.response && err.response.status === httpStatus.UNAUTHORIZED) {

            // if authorized, then try to obtain auth tokens and try the request again.
            const wasSuccessful = await this._obtainAuthTokens();
            if (wasSuccessful) {
               try {
                  return await doRequest();
               }
               catch (err) {
                  self._log.error("Failed to execute request to [" + url + "], even after obtaining tokens. Giving up. Error: ", err.message);
                  throw err;
               }
            }
            else {
               self._log.error("Failed to refresh or obtain auth tokens, throwing original error");
               throw err;
            }
         }
         else {
            throw err;
         }
      }
   }

   _esdrGet(url, willIncludeAuthorization) {
      return this._callEsdr(url, 'get', null, willIncludeAuthorization);
   }

   _esdrPost(url, data, willIncludeAuthorization = false) {
      return this._callEsdr(url, 'post', data, willIncludeAuthorization);
   }

   async _ensureTokensAreLoaded() {
      if (!this._tokenStore.hasTokens()) {
         if (!await this._tokenStore.load()) {
            await this._obtainAuthTokens();
         }
      }
   }

   async _refreshTokens() {
      try {
         const response = await this._esdrPost('/oauth/token',
                                               {
                                                  grant_type : "refresh_token",
                                                  client_id : this._client.id,
                                                  client_secret : this._client.secret,
                                                  refresh_token : this._tokenStore.getRefreshToken()
                                               });

         // noinspection JSCheckFunctionSignatures
         return await this._tokenStore.save(this._tokenStore.getUserId(),
                                            response.data['access_token'],
                                            response.data['refresh_token']);
      }
      catch (err) {
         this._log.error("Error refreshing tokens for user [" + this._user.username + "]: ", err.message);
         return false;
      }
   }

   async _authenticate() {
      try {
         const response = await this._esdrPost('/oauth/token',
                                               {
                                                  grant_type : "password",
                                                  client_id : this._client.id,
                                                  client_secret : this._client.secret,
                                                  username : this._user.username,
                                                  password : this._user.password
                                               });

         return await this._tokenStore.save(response.data['userId'],
                                            response.data['access_token'],
                                            response.data['refresh_token']);
      }
      catch (err) {
         this._log.error("Error authenticating user [" + this._user.username + "]: ", err.message);
         return false;
      }
   }

   async _obtainAuthTokens() {
      if (this._tokenStore.getRefreshToken()) {
         this._log.debug("Attempting to refresh the access token...");
         const wasRefreshSuccessful = await this._refreshTokens();
         if (wasRefreshSuccessful) {
            return wasRefreshSuccessful;
         }
         else {
            this._log.debug("Refreshing tokens failed, so will attempt to authenticate to obtain tokens");
         }
      }

      this._log.debug("Authenticating to obtain tokens...");
      return await this._authenticate();
   }

   async getProduct(productNameOrId, fields = null) {
      let fieldsClause = Array.isArray(fields) && fields.length > 0 ? '?fields=' + fields.join(',') : '';
      const response = await this._esdrGet('/api/v1/products/' + productNameOrId + fieldsClause);
      return response.data.data;
   }

   async createDevice(productNameOrId, device) {
      const response = await this._esdrPost('/api/v1/products/' + productNameOrId + '/devices', device, true);
      return response.data.data;
   }

   async createFeed(deviceId, feed) {
      const response = await this._esdrPost('/api/v1/devices/' + deviceId + '/feeds', feed, true);
      return response.data.data;
   }

   async getUserDevicesForProduct(productId, fields, orderBy) {
      const orderByClause = TypeUtils.isNonEmptyString(orderBy) ? '&orderBy=' + orderBy : '';
      const response = await this._esdrGet('/api/v1/devices' +
                                           '?where=productId=' + productId +
                                           '&fields=' + fields.join(',') +
                                           orderByClause,
                                           true);
      return response.data.data;
   }

   async getFeedsForDevice(deviceId, fields, orderBy) {
      const orderByClause = TypeUtils.isNonEmptyString(orderBy) ? '&orderBy=' + orderBy : '';

      const response = await this._esdrGet('/api/v1/feeds' +
                                           '?where=deviceId=' + deviceId +
                                           '&fields=' + fields.join(',') +
                                           orderByClause,
                                           true);
      return response.data.data;
   }

   async getUserFeedsForProduct(productId, fields, orderBy) {
      const orderByClause = TypeUtils.isNonEmptyString(orderBy) ? '&orderBy=' + orderBy : '';

      // first make sure the tokens are loaded because we need the user ID in order to create the where clause
      await this._ensureTokensAreLoaded();
      const response = await this._esdrGet('/api/v1/feeds' +
                                           '?whereAnd=userId=' + this._tokenStore.getUserId() +
                                           ',productId=' + productId +
                                           '&fields=' + fields.join(',') +
                                           orderByClause,
                                           true);
      return response.data.data;
   }
}

module.exports.EsdrRequestError = EsdrRequestError;
module.exports.EsdrEntityExistsError = EsdrEntityExistsError;
module.exports.EsdrNoResponseError = EsdrNoResponseError;
module.exports.EsdrUnexpectedError = EsdrUnexpectedError;
module.exports.TokenStorageStrategy = TokenStorageStrategy;
module.exports.InMemoryTokenStorageStrategy = InMemoryTokenStorageStrategy;
module.exports.JsonFileTokenStorageStrategy = JsonFileTokenStorageStrategy;
module.exports.EsdrClient = EsdrClient;