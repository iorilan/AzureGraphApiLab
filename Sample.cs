using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using System.Web;
using System.Web.Caching;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Web.Http.ModelBinding;
using System.Web.Http.Validation.Providers;
using System.Web.Mvc;
using azureADRestApi.Models;
using log4net;
using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security.OAuth.Messages;
using Newtonsoft.Json;

namespace azureADRestApi.Controllers
{

    internal class AzureADGlobalConstants
    {
        public const string AuthString = "https://login.microsoftonline.com/";
        // public const string ResourceUrl = "https://graph.windows.net";
        public const string GraphUrl = "https://graph.microsoft.com";

        public const string GraphServiceObjectId = "00000002-0000-0000-c000-000000000000";
    }

    [EnableCors(origins: "*", headers: "*", methods: "*")]
    public class YourAdLoginController : ApiController
    {
        private ILog _log = LogManager.GetLogger(typeof(YourAdLoginController));
        public string IdTokenFromSession
        {
            get
            {
                var t = HttpContext.Current.Session["idtoken"];
                if (t == null)
                {
                    return string.Empty;
                }

                return t.ToString();
            }
        }
        public void UpdateToken(string idtoken)
        {
            if (HttpContext.Current.Session["idtoken"] == null)
            {
                HttpContext.Current.Session["idtoken"] = idtoken;
            }
            else
            {
                HttpContext.Current.Session.Add("idtoken", idtoken);
            }
        }
        /// <summary>
        /// Login with username/password
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        [System.Web.Http.Route("api/ad/login/")]
        public IHttpActionResult Login([FromBody]LoginRequest loginRequest)
        {
            try
            {
                var username = loginRequest.UserName;
                var password = loginRequest.Password;

                string directoryName = AzureADAppConstants.TenantName;
                string clientId = AzureADAppConstants.ClientId;
                var credentials = new UserPasswordCredential(string.Format("{0}", username), password);
                var authenticationContext = new AuthenticationContext(AzureADGlobalConstants.AuthString + directoryName);
                var loginResult = authenticationContext.AcquireTokenAsync(AzureADGlobalConstants.GraphUrl, clientId, credentials).Result;

                var token = loginResult.AccessToken;
                var userProfile = GetUserById(token, loginResult.UserInfo.UniqueId);
                var photo = GetUserPhoto(token, loginResult.UserInfo.UniqueId);
                userProfile.Photo = photo;

                // cache idtoken
                UpdateToken(loginResult.IdToken);

                return Ok(new LoginResponse()
                {
                    IsSuccess = true,
                    ErrorMessage = "",
                    Data = userProfile,
                });
            }
            catch (Exception ex)
            {
                _log.Error(ex);
                return Ok(new LoginResponse()
                {
                    IsSuccess = false,
                    ErrorMessage = ex.Message
                });
            }
        }

        [System.Web.Http.HttpPost]
        [System.Web.Http.Route("api/ad/allusers/")]
        public IHttpActionResult GetAllUsers([FromBody]UserPagingRequest request)
        {
            try
            {


                var tryGetToken = IdTokenFromSession;
                if (string.IsNullOrWhiteSpace(tryGetToken))
                {
                    tryGetToken = RefreshTokenWithAdminLogin();
                    UpdateToken(tryGetToken);
                }

                return DoUserPaging(request, tryGetToken);
            }
            catch (Exception ex)
            {
                // assume that token has been expired
                try
                {
                    var idtoken = RefreshTokenWithAdminLogin();
                    UpdateToken(idtoken);

                    return DoUserPaging(request, idtoken);
                }
                catch (Exception ex2)
                {
                    _log.Error(ex2);
                    return InternalServerError();
                }
                
            }
        }


        [System.Web.Http.Route("api/ad/search/")]
        public IHttpActionResult UserDetail([FromBody]QueryRequest request)
        {
            try
            {

                var tryGetToken = IdTokenFromSession;
                if (string.IsNullOrWhiteSpace(tryGetToken))
                {
                    tryGetToken = RefreshTokenWithAdminLogin();
                    UpdateToken(tryGetToken);
                }


                return DoGetDetail(request, tryGetToken);
            }
            catch (Exception ex)
            {
                try
                {
                    // assume that token has been expired
                    var idtoken = RefreshTokenWithAdminLogin();
                    UpdateToken(idtoken);
                    return DoGetDetail(request, idtoken);
                }
                catch (Exception ex2)
                {
                    _log.Error(ex);
                    return InternalServerError(ex);
                }
            }
        }

        private IHttpActionResult DoGetDetail(QueryRequest request, string tryGetToken)
        {
            string directoryName = AzureADAppConstants.TenantName;
            string clientId = AzureADAppConstants.ClientId;
            var credentials = new UserAssertion(tryGetToken);
            var authenticationContext = new AuthenticationContext(AzureADGlobalConstants.AuthString + directoryName);
            var loginResult = authenticationContext.AcquireTokenAsync(AzureADGlobalConstants.GraphUrl, clientId, credentials)
                .Result;

            var token = loginResult.AccessToken;

            var userProfiles = GetUserBy(token, request.Keyword);
            foreach (var profile in userProfiles)
            {
                var photo = GetUserPhoto(token, profile.Id);
                profile.Photo = photo;
            }

            return Ok(new QueryResponse()
            {
                IsSuccess = true,
                ErrorMessage = "",
                Data = userProfiles,
            });
        }

        private IHttpActionResult DoUserPaging(UserPagingRequest request, string tryGetToken)
        {
            string directoryName = AzureADAppConstants.TenantName;
            string clientId = AzureADAppConstants.ClientId;
            var credentials = new UserAssertion(tryGetToken);
            var authenticationContext = new AuthenticationContext(AzureADGlobalConstants.AuthString + directoryName);
            var loginResult = authenticationContext.AcquireTokenAsync(AzureADGlobalConstants.GraphUrl, clientId, credentials)
                .Result;

            var token = loginResult.AccessToken;


            ProfileResultWrapper result = null;
            string skipToken = "";
            
            using (var httpClient = new HttpClient())
            {
                var baseUrl = "https://graph.microsoft.com/v1.0/users?";

                var filterString = string.Format("$top={0}", request.PageSize);

                // sample :
                //https://graph.microsoft.com/v1.0/users?$top=10&$skiptoken=X%274453707
                // 

                if (!string.IsNullOrWhiteSpace(request.AzureToken))
                {
                    filterString += "&$skiptoken=" + request.AzureToken;
                }

                httpClient.BaseAddress = new Uri(baseUrl + filterString);
                httpClient.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse("Bearer " + token);
                var graphRet = httpClient.GetAsync("").Result;
                var json = graphRet.Content.ReadAsStringAsync().Result;

                result = JsonConvert.DeserializeObject<ProfileResultWrapper>(json);

                var i = result.SkipToken.IndexOf("skiptoken=");
                var st = "skiptoken=";
                skipToken = result.SkipToken.Substring(i + st.Length, result.SkipToken.Length - i - st.Length);
            }
            foreach (var profile in result.Value)
            {
                var photo = GetUserPhoto(token, profile.Id);
                profile.Photo = photo;
            }

            return Ok(new PagingQueryResponse()
            {
                IsSuccess = true,
                ErrorMessage = "",
                Data = result.Value,
                SkipToken = skipToken
            });
        }


        private string RefreshTokenWithAdminLogin()
        {
            var username = "xxx";
            var password = "xxx";

            string directoryName = AzureADAppConstants.TenantName;
            string clientId = AzureADAppConstants.ClientId;
            //var credentials = new UserPasswordCredential(string.Format("{0}@{1}", username, directoryName), password);
            var credentials = new UserPasswordCredential(string.Format("{0}", username), password);
            //var authenticationContext = new AuthenticationContext(AzureADGlobalConstants.AuthString + directoryName);
            var authenticationContext = new AuthenticationContext(AzureADGlobalConstants.AuthString + directoryName);
            var loginResult = authenticationContext.AcquireTokenAsync(AzureADGlobalConstants.GraphUrl, clientId, credentials).Result;

            return loginResult.IdToken;
        }


        private byte[] GetUserPhoto(string token, string objId)
        {
            using (var httpClient = new HttpClient())
            {
                httpClient.BaseAddress = new Uri("https://graph.microsoft.com/v1.0/users/");
                httpClient.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse("Bearer " + token);
                var x = httpClient.GetAsync(String.Format("{0}/photo/$value", objId)).Result;
                var bytes = x.Content.ReadAsByteArrayAsync().Result;

                return bytes;
            }
        }

        private IList<UserProfileResult> GetUserBy(string token, string keyword)
        {
            if (string.IsNullOrWhiteSpace(keyword))
            {
                return new List<UserProfileResult>();
            }

            
            using (var httpClient = new HttpClient())
            {
                var baseUrl = "https://graph.microsoft.com/v1.0/users?";
                var filterString = string.Format("$filter=accountEnabled eq true and startswith(mail,'{0}')", keyword);

                httpClient.BaseAddress = new Uri(baseUrl + filterString);
                httpClient.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse("Bearer " + token);
                var graphRet = httpClient.GetAsync("").Result;
                var json = graphRet.Content.ReadAsStringAsync().Result;

                var all = JsonConvert.DeserializeObject<ProfileResultWrapper>(json).Value;
                //var filtered = all.Value.Where(x => x.Mail != null && x.Mail.Contains(keyword)).ToList();
                //var filtered = all.Value.Where(x => x.Mail != null && x.Mail.Contains(keyword) ||
                //                                    x.BusinessPhones != null && x.BusinessPhones.Count(x1 => x1.Contains(keyword)) > 0 ||
                //                                    x.DisplayName != null && x.DisplayName.Contains(keyword) ||
                //                                    x.GivenName != null && x.GivenName.Contains(keyword) ||
                //                                    x.Surname != null && x.Surname.Contains(keyword) ||
                //                                    x.MobilePhone != null && x.MobilePhone.Contains(keyword) ||
                //                                    x.UserPrincipalName != null && x.UserPrincipalName.Contains(keyword) ||
                //                                    x.JobTitle != null && x.JobTitle.Contains(keyword)).ToList();
                return all;
            }
        }

        private UserProfileResult GetUserById(string token, string objId)
        {
            using (var httpClient = new HttpClient())
            {
                httpClient.BaseAddress = new Uri("https://graph.microsoft.com/v1.0/users/");
                httpClient.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse("Bearer " + token);
                var x = httpClient.GetAsync(objId).Result;
                var json = x.Content.ReadAsStringAsync().Result;

                var ret = JsonConvert.DeserializeObject<UserProfileResult>(json);
                return ret;
            }
        }
        // Get User photo
        //https://graph.microsoft.com/v1.0/users/9db0918d-a02b-4e41-b50f-0576dfdb06c4/photo/$value

    }



    internal class AzureADAppConstants
    {
        /// <summary>
        /// The application id ,you can login to azure portal ->
        /// Azure Active Directory ->
        /// Registered Apps -> click the app
        /// Native1
        /// </summary>
        public const string ClientId = "xxx"; //Yours


        /// <summary>
        /// Login to your azure portal ->
        /// Azure Active Directory ->
        /// Registered Apps -> click the app 
        /// keys -> add new
        /// </summary>

        /// <summary>
        /// this is used to construct the login user name:
        /// e.g.  someone@xxx.onmicrosoft.com
        /// </summary>
        public const string TenantName = "YourAD.onmicrosoft.com"; //Yours

        /// <summary>
        /// you can get this value form below steps :
        /// Login to your azure portal ->
        /// Azure Active Directory ->
        /// Properties -> DirectoryId
        /// </summary>

        public const string TenantId = "xxx"; //Yours
    }











    //public class RefreshTokenRequest
    //{
    //    public string IdToken { get; set; }
    //}
    /// <summary>
    /// Login with idToken
    /// </summary>
    /// <param name="idToken"></param>
    /// <returns></returns>
    //[System.Web.Http.Route("api/ad/refreshtoken/")]
    //public IHttpActionResult Login(RefreshTokenRequest request)
    //{
    //    try
    //    {
    //        var idToken = request.IdToken;

    //        string directoryName = AzureADAppConstants.TenantName;
    //        string clientId = AzureADAppConstants.ClientId;
    //        var credentials = new UserAssertion(idToken);
    //        var authenticationContext = new AuthenticationContext(AzureADGlobalConstants.AuthString + directoryName);
    //        var result = authenticationContext.AcquireTokenAsync(AzureADGlobalConstants.ResourceUrl, clientId, credentials).Result;
    //        var tokenGetter = Task.Run(() => { return result.AccessToken; });
    //        // get more details
    //        var userDetail = GetUserDetailById(tokenGetter, result.UserInfo.UniqueId);

    //        return Ok(new LoginResult()
    //        {
    //            IsSuccess = true,
    //            Data = result,
    //            ErrorMessage = "",
    //            UserDetail = userDetail
    //        });
    //    }
    //    catch (Exception ex)
    //    {
    //        return Ok(new LoginResult()
    //        {
    //            IsSuccess = false,
    //            ErrorMessage = ex.Message
    //        });
    //    }
    //}

}
