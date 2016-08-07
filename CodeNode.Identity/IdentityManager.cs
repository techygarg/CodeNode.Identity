using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using System.Web;
using CodeNode.Identity.Database;
using CodeNode.Identity.Exceptions;
using CodeNode.Identity.Models;
using CodeNode.Identity.Provider;
using CodeNode.Identity.Services;
using CodeNode.Identity.Store;
using CodeNode.Identity.Utilities;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;

namespace CodeNode.Identity
{
    /// <summary>
    ///     IdentityManager with default user as ApplicationUser
    /// </summary>
    public class IdentityManager : IdentityManager<ApplicationUser>
    {
        /// <summary>
        ///     Initializes a new instance of the <see cref="IdentityManager" /> class.
        /// </summary>
        /// <param name="configOptions">The configuration options.</param>
        public IdentityManager(IdentityConfigOptions<ApplicationUser> configOptions = null)
            : base(configOptions)
        {
        }
    }

    /// <summary>
    ///     Generic implementation of IdentityManager for user
    /// </summary>
    /// <typeparam name="TUser">The type of the user.</typeparam>
    public class IdentityManager<TUser> : IDisposable
        where TUser : ApplicationUser, IUser<Guid>
    {
        #region Ctor

        public IdentityManager(IdentityConfigOptions<TUser> configOptions = null)
        {
            if (configOptions == null)
                configOptions = new IdentityConfigOptions<TUser>();

            _dbContext = new DatabaseContext<TUser>();
            ApplicationUserManager = GetUserManager();
            ApplicationRoleManager = new RoleManager<ApplicationRole, Guid>(new ApplicationRoleStore<TUser>(_dbContext));

            ApplicationUserManager.UserValidator = GetDefaultUserValidator(configOptions.UserValidatorExtender);
            _dataProtectorTokenProvider = configOptions.UserTokenProvider ?? GetDefaultUserTokenProvider();
            ApplicationUserManager.UserTokenProvider = configOptions.UserTokenProvider ?? GetDefaultUserTokenProvider();
            ApplicationUserManager.PasswordValidator = configOptions.PasswordValidator ?? GetDefaultPasswordValidator();
            ApplicationUserManager.EmailService = configOptions.EmailService ?? new EmailService();
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _dbContext.Dispose();
            ApplicationUserManager.Dispose();
            ApplicationRoleManager.Dispose();
        }

        #endregion

        #region Private Variables

        private readonly DatabaseContext<TUser> _dbContext;

        private readonly DataProtectorTokenProvider<TUser, Guid> _dataProtectorTokenProvider;

        private readonly string purposeAccountActivation = "AccountActivation";

        #endregion

        #region Public Variables

        /// <summary>
        ///     Reference of UserManager
        /// </summary>
        public UserManager<TUser, Guid> ApplicationUserManager { get; }

        /// <summary>
        ///     Reference of RoleManager
        /// </summary>
        public RoleManager<ApplicationRole, Guid> ApplicationRoleManager { get; }

        #endregion

        #region Public Methods

        #region User,Role 

        /// <summary>
        ///     Checks if username exists.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <returns></returns>
        public bool CheckIfUserNameExists(string username)
        {
            var applicationUser = ApplicationUserManager.FindByName(username);
            return applicationUser != null;
        }

        /// <summary>
        ///     Creates the user.
        /// </summary>
        /// <param name="user">The user.</param>
        public void CreateUser(TUser user)
        {
            CreateAppUser(user, null, null);
        }

        /// <summary>
        ///     Creates the user and add to specified roles.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="userRoles">The user roles.</param>
        public void CreateUser(TUser user, IList<string> userRoles)
        {
            CreateAppUser(user, userRoles, null);
        }

        /// <summary>
        ///     Creates the user, add to specified roles and set password.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="userRoles">The user roles.</param>
        /// <param name="password">The password.</param>
        public void CreateUser(TUser user, IList<string> userRoles, string password)
        {
            Utils.EnsureNotNull(password, "password");

            CreateAppUser(user, userRoles, password);
        }

        /// <summary>
        ///     Updates the user.
        /// </summary>
        /// <param name="user">The user.</param>
        public void UpdateUser(TUser user)
        {
            Utils.EnsureNotNull(user, "user");
            var result = ApplicationUserManager.Update(user);
            ProcessIdentityResult(result);
        }

        /// <summary>
        ///     Updates the user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="roles">The roles.</param>
        /// <param name="removeUserExistingRoles">if set to <c>true</c> [remove user existing roles].</param>
        public void UpdateUser(TUser user, IList<string> roles, bool removeUserExistingRoles)
        {
            UpdateUser(user);

            if (roles != null && roles.Any())
            {
                AddRolesToUser(roles, user.Id, removeUserExistingRoles);
            }
        }

        /// <summary>
        ///     Creates the role.
        /// </summary>
        /// <param name="roleName">Name of the role.</param>
        /// <exception cref="ArgumentNullException">roleName</exception>
        public void CreateRole(string roleName)
        {
            Utils.EnsureNotNull(roleName, "roleName");

            var role = ApplicationRoleManager.FindByName(roleName);
            if (role != null)
                throw new RoleException(string.Format("Role with name {0} already exist.", roleName),
                    ErrorCodes.RoleAlreadyExist);

            role = new ApplicationRole(roleName);
            var result = ApplicationRoleManager.Create(role);
            ProcessIdentityResult(result);
        }

        /// <summary>
        ///     Creates the roles.
        /// </summary>
        /// <param name="roles">The roles.</param>
        /// <exception cref="ArgumentNullException">roles</exception>
        public void CreateRoles(IList<string> roles)
        {
            Utils.EnsureNotNull(roles, "roles");

            using (var transaction = _dbContext.Database.BeginTransaction())
            {
                foreach (var role in roles)
                {
                    CreateRole(role);
                }
                transaction.Commit();
            }
        }

        /// <summary>
        ///     Updates the role.
        /// </summary>
        /// <param name="currentRoleName">Name of the current role.</param>
        /// <param name="newRoleName">New name of the role.</param>
        /// <exception cref="ArgumentNullException">
        ///     currentRoleName
        ///     or
        ///     newRoleName
        /// </exception>
        /// <exception cref="IdentityException"></exception>
        public void UpdateRole(string currentRoleName, string newRoleName)
        {
            Utils.EnsureNotNull(currentRoleName, "currentRoleName");
            Utils.EnsureNotNull(newRoleName, "newRoleName");

            var role = ApplicationRoleManager.FindByName(currentRoleName);
            if (role == null)
                throw new RoleException($"Role {currentRoleName} not found", ErrorCodes.RoleNotExist);

            role.Name = newRoleName;
            var result = ApplicationRoleManager.Update(role);
            ProcessIdentityResult(result);
        }

        /// <summary>
        ///     Updates the role.
        /// </summary>
        /// <param name="role">The role.</param>
        /// <exception cref="ArgumentNullException">role</exception>
        public void UpdateRole(ApplicationRole role)
        {
            Utils.EnsureNotNull(role, "role");

            var result = ApplicationRoleManager.Update(role);
            ProcessIdentityResult(result);
        }

        /// <summary>
        ///     Adds the roles to user.
        /// </summary>
        /// <param name="roles">The roles.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="removeUserExistingRoles">if set to <c>true</c> [remove existing roles].</param>
        public void AddRolesToUser(IList<string> roles, Guid userId, bool removeUserExistingRoles)
        {
            Utils.EnsureNotNull(roles, "roles");
            Utils.EnsureNotNull(userId, "userId");

            using (var transaction = _dbContext.Database.BeginTransaction(IsolationLevel.ReadCommitted))
            {
                if (removeUserExistingRoles)
                {
                    RemoveUserRoles(userId);
                }

                var result = ApplicationUserManager.AddToRoles(userId, roles.ToArray());
                ProcessIdentityResult(result);
                transaction.Commit();
            }
        }

        /// <summary>
        ///     Adds the role to user.
        /// </summary>
        /// <param name="role">The role.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="removeUserExistingRoles">if set to <c>true</c> [remove user existing roles].</param>
        public void AddRoleToUser(string role, Guid userId, bool removeUserExistingRoles)
        {
            Utils.EnsureNotNull(role, "role");
            Utils.EnsureNotNull(userId, "userId");

            using (var transaction = _dbContext.Database.BeginTransaction(IsolationLevel.ReadCommitted))
            {
                if (removeUserExistingRoles)
                {
                    RemoveUserRoles(userId);
                }

                var result = ApplicationUserManager.AddToRole(userId, role);
                ProcessIdentityResult(result);
                transaction.Commit();
            }
        }

        /// <summary>
        ///     Removes the user roles.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        public void RemoveUserRoles(Guid userId)
        {
            Utils.EnsureNotNull(userId, "userId");

            var currentRoles = ApplicationUserManager.GetRoles(userId);
            if (currentRoles != null && currentRoles.Any())
            {
                var result = ApplicationUserManager.RemoveFromRoles(userId, currentRoles.ToArray());
                ProcessIdentityResult(result);
            }
        }

        /// <summary>
        ///     Deletes the application user by application user id.
        /// </summary>
        /// <param name="userId">The application user identifier or username.</param>
        /// <exception cref="System.Exception"></exception>
        public void DeleteUser(Guid userId)
        {
            Utils.EnsureNotNull(userId, "userId");

            var applicationUser = ApplicationUserManager.FindById(userId);

            if (applicationUser == null)
                throw new UserNotExistException("UserId not found.", ErrorCodes.UserIdNotFound);

            RemoveUserRoles(applicationUser.Id);
            var result = ApplicationUserManager.Delete(applicationUser);
            ProcessIdentityResult(result);
        }

        /// <summary>
        ///     Deletes the user by user name.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <exception cref="Exception">
        /// </exception>
        public void DeleteUser(string userName)
        {
            Utils.EnsureNotNull(userName, "userName");

            var applicationUser = ApplicationUserManager.FindByName(userName);

            if (applicationUser == null)
                throw new UserNotExistException("User name not found.", ErrorCodes.UserNameNotFound);

            RemoveUserRoles(applicationUser.Id);
            var result = ApplicationUserManager.Delete(applicationUser);
            ProcessIdentityResult(result);
        }

        #endregion

        #region Password,SignIn

        /// <summary>
        ///     Changes the application user password.
        /// </summary>
        /// <param name="userId">The application user identifier.</param>
        /// <param name="currentPassword">The current password.</param>
        /// <param name="newPassword">The new password.</param>
        public void ChangeUserPassword(Guid userId, string currentPassword, string newPassword)
        {
            Utils.EnsureNotNull(userId, "userId");
            Utils.EnsureNotNull(currentPassword, "currentPassword");
            Utils.EnsureNotNull(newPassword, "newPassword");

            var result = ApplicationUserManager.ChangePassword(userId, currentPassword, newPassword);
            ProcessIdentityResult(result);
        }

        /// <summary>
        ///     Changes the application user password.
        /// </summary>
        /// <param name="userId">The application user identifier.</param>
        /// <param name="newPassword">The new password.</param>
        public void ChangeUserPassword(Guid userId, string newPassword)
        {
            Utils.EnsureNotNull(userId, "userId");
            Utils.EnsureNotNull(newPassword, "newPassword");

            using (var transaction = _dbContext.Database.BeginTransaction(IsolationLevel.ReadCommitted))
            {
                var result = ApplicationUserManager.RemovePassword(userId);
                ProcessIdentityResult(result);

                result = ApplicationUserManager.AddPassword(userId, newPassword);
                ProcessIdentityResult(result);

                transaction.Commit();
            }
        }

        /// <summary>
        ///     Validate user credential.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        public UserAuthenticationResult<TUser> ValidateUserCredentials(string username, string password)
        {
            var isSucceeded = false;
            var error = string.Empty;

            var user = ApplicationUserManager.FindByName(username);
            if (user != null)
            {
                if (user.IsActive)
                {
                    if (!ApplicationUserManager.IsLockedOut(user.Id))
                    {
                        if (ApplicationUserManager.CheckPassword(user, password))
                        {
                            ApplicationUserManager.ResetAccessFailedCount(user.Id);
                            isSucceeded = true;
                        }
                        else
                        {
                            error = "Username or password is invalid.";

                            if (AppSettingsValueProvider.ShouldLockOutAccount)
                            {
                                //If lockout is requested, increment access failed count which might lock out the user
                                ApplicationUserManager.AccessFailed(user.Id);
                                if (ApplicationUserManager.IsLockedOut(user.Id))
                                {
                                    error = "Username or password is invalid and account has locked out.";
                                }
                            }
                        }
                    }
                    else
                    {
                        error = "Account is currently locked.";
                    }
                }
                else
                {
                    error = "Account is not active";
                }
            }
            else
            {
                error = "Username or password is invalid.";
            }

            var result = new UserAuthenticationResult<TUser>
            {
                IsSucceeded = isSucceeded,
                Error = error,
                User = user
            };

            return result;
        }

        /// <summary>
        ///     Signs the in web application through form authentication.
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <param name="isPersistent"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public SignInStatus CookieSignIn(string userName, string password, bool isPersistent, IOwinContext context)
        {
            Utils.EnsureNotNull(userName, "userName");
            Utils.EnsureNotNull(password, "password");
            Utils.EnsureNotNull(context, "context");

            var user = ApplicationUserManager.FindByName(userName);

            if (user == null)
                throw new UserNotExistException("User name not found.", ErrorCodes.UserNameNotFound);

            if (!user.IsActive)
                throw new IdentityException("User is not active.", ErrorCodes.UserNotActive);

            var signInManager = new SignInManager<TUser, Guid>(ApplicationUserManager, context.Authentication);
            return signInManager.PasswordSignIn(userName, password, isPersistent,
                AppSettingsValueProvider.ShouldLockOutAccount);
        }

        #endregion

        #region Mail notifications and handlers

        /// <summary>
        ///     Reset password
        /// </summary>
        /// <param name="code"></param>
        /// <param name="token"></param>
        /// <param name="password"></param>
        public void ResetPassword(string code, string token, string password)
        {
            Utils.EnsureNotNull(code, "code");
            Utils.EnsureNotNull(token, "token");
            Utils.EnsureNotNull(password, "password");

            var decodedCode = HttpUtility.UrlDecode(code);
            var decodedToken = HttpUtility.UrlDecode(token);

            var userId = Guid.Parse(DecryptData(decodedCode));
            var result = ApplicationUserManager.ResetPassword(userId, SanitizeToken(decodedToken), password);
            ProcessIdentityResult(result);
        }

        /// <summary>
        ///     Send password reset mail to provided e-mail
        /// </summary>
        /// <param name="userEmail">The user email.</param>
        /// <param name="additionalKeyTextList">The additional key text list to add in email body.</param>
        /// <exception cref="UserNotExistException">User with provided email not found.</exception>
        public void SendPasswordResetMail(string userEmail,
            List<KeyValuePair<string, string>> additionalKeyTextList = null)
        {
            Utils.EnsureNotNull(userEmail, "userEmail");

            var user = ApplicationUserManager.FindByEmail(userEmail);
            if (user == null)
                throw new UserNotExistException("User with provided email not found.", ErrorCodes.UserEmailNotFound);

            var token = ApplicationUserManager.GeneratePasswordResetToken(user.Id);

            SendTokenEmail(user.Id, token,
                AppSettingsValueProvider.ResetPasswordCallBackLink,
                AppSettingsValueProvider.ResetPasswordEmailTemplatePath,
                AppSettingsValueProvider.ResetPasswordMailSubject,
                additionalKeyTextList);
        }

        /// <summary>
        ///     Send email to re activate account in case it was inactivated by admin/business requirement
        /// </summary>
        /// <param name="userId">User Id</param>
        /// <param name="additionalKeyTextList">The additional key text list to add in email body.</param>
        /// <exception cref="UserNotExistException">User Id Not Found.</exception>
        public void SendUserActivationMail(Guid userId,
            List<KeyValuePair<string, string>> additionalKeyTextList = null)
        {
            Utils.EnsureNotNull(userId, "userId");

            var user = ApplicationUserManager.FindById(userId);
            if (user == null)
                throw new UserNotExistException("User Id Not Found.", ErrorCodes.UserIdNotFound);

            var token = ApplicationUserManager.GenerateUserToken(purposeAccountActivation, user.Id);

            SendTokenEmail(userId, token,
                AppSettingsValueProvider.AccountActivationCallBackLink,
                AppSettingsValueProvider.AccountActivationTemplatePath,
                AppSettingsValueProvider.AccountActivationMailSubject,
                additionalKeyTextList);
        }

        /// <summary>
        ///     Activate account by marking IsActive to true.
        /// </summary>
        /// <param name="code"></param>
        /// <param name="token"></param>
        public void SetUserIsActiveFlag(string code, string token)
        {
            Utils.EnsureNotNull(code, "code");
            Utils.EnsureNotNull(token, "token");

            var decodedCode = HttpUtility.UrlDecode(code);
            var decodedToken = HttpUtility.UrlDecode(token);

            var userId = Guid.Parse(DecryptData(decodedCode));
            var isTokenValid = ApplicationUserManager.VerifyUserToken(userId, purposeAccountActivation,
                SanitizeToken(decodedToken));

            if (!isTokenValid)
                throw new IdentityException("Invalid User Token.", ErrorCodes.InvalidToken);

            var user = ApplicationUserManager.FindById(userId);
            if (user == null)
                throw new UserNotExistException("User Id Not Found.", ErrorCodes.UserIdNotFound);

            user.IsActive = true;
            user.LastLoggedOn = DateTime.Now;
            user.LastModifiedOn = DateTime.Now;
            var result = ApplicationUserManager.Update(user);

            ProcessIdentityResult(result);
            UpdateSecurityStamp(user.Id);
        }

        /// <summary>
        ///     Sends the email confirmation mail.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="additionalKeyTextList">The additional key text list to add in email body.</param>
        /// <exception cref="ArgumentNullException">userId</exception>
        public void SendEmailConfirmationMail(Guid userId,
            List<KeyValuePair<string, string>> additionalKeyTextList = null)
        {
            Utils.EnsureNotNull(userId, "userId");

            var token = ApplicationUserManager.GenerateEmailConfirmationToken(userId);

            SendTokenEmail(userId, token,
                AppSettingsValueProvider.EmailConfirmationCallBackLink,
                AppSettingsValueProvider.EmailConfirmationTemplatePath,
                AppSettingsValueProvider.EmailConfirmationMailSubject,
                additionalKeyTextList);
        }

        /// <summary>
        ///     Confirms the user email.
        /// </summary>
        /// <param name="code">The code.</param>
        /// <param name="token">The token.</param>
        public void ConfirmUserEmail(string code, string token)
        {
            ConfirmEmailAndSetPasswordInternal(code, token, null);
        }

        /// <summary>
        ///     Confirms the user email and set password.
        /// </summary>
        /// <param name="code">The code.</param>
        /// <param name="token">The token.</param>
        /// <param name="password">The password.</param>
        /// <exception cref="ArgumentNullException">password</exception>
        public void ConfirmUserEmailAndSetPassword(string code, string token, string password)
        {
            Utils.EnsureNotNull(password, "password");
            ConfirmEmailAndSetPasswordInternal(code, token, password);
        }

        #endregion

        #region Two Factor Authentication

        /// <summary>
        ///     Sends the two factor code.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        public void SendTwoFactorCode(Guid userId)
        {
            Utils.EnsureNotNull(userId, "userId");

            var token = ApplicationUserManager.GenerateTwoFactorToken(userId, IdentityConstants.EmailTwoFactorProviderName);
            ApplicationUserManager.NotifyTwoFactorToken(userId, IdentityConstants.EmailTwoFactorProviderName, token);
        }

        /// <summary>
        ///     Validates the two factor token.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="code">The code.</param>
        /// <param name="provider">The provider.</param>
        /// <param name="invalidateTokenOnSuccess">if set to <c>true</c> [invalidate token on success].</param>
        /// <returns></returns>
        public SignInStatus ValidateTwoFactorToken(Guid userId, string code, string provider,
            bool invalidateTokenOnSuccess = true)
        {
            Utils.EnsureNotNull(userId, "userId");

            if (ApplicationUserManager.IsLockedOut(userId))
            {
                return SignInStatus.LockedOut;
            }

            if (ApplicationUserManager.VerifyTwoFactorToken(userId, provider, code))
            {
                // When token is verified correctly, clear the access failed count used for lockout
                ApplicationUserManager.ResetAccessFailedCount(userId);

                if (invalidateTokenOnSuccess)
                    UpdateSecurityStamp(userId);

                return SignInStatus.Success;
            }

            // If the token is incorrect, record the failure which also may cause the user to be locked out
            ApplicationUserManager.AccessFailed(userId);
            return SignInStatus.Failure;
        }

        #endregion

        #region Utils

        /// <summary>
        ///     Gets the current logged in user from current HttpContext.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidUserInformationException">Current user identity not found.</exception>
        /// <exception cref="UserNotExistException">Current user not found.</exception>
        public TUser GetCurrentUser()
        {
            var userId = IdentityClaimsHelper.GetCurrentUserId();

            if (Guid.Empty.Equals(userId))
                throw new InvalidUserInformationException("Current user identity not found.");

            var user = ApplicationUserManager.Users.FirstOrDefault(x => x.Id == userId);

            if (user == null)
                throw new UserNotExistException("Current user not found.", ErrorCodes.CurrentUserNotFound);

            return user;
        }

        /// <summary>
        ///     Processes the identity result.
        /// </summary>
        /// <param name="result">The result.</param>
        /// <exception cref="UserNotExistException">
        /// </exception>
        /// <exception cref="InvalidUserInformationException">
        /// </exception>
        /// <exception cref="InvalidPasswordException">
        /// </exception>
        /// <exception cref="IdentityException">
        /// </exception>
        public static void ProcessIdentityResult(IdentityResult result)
        {
            if (result.Succeeded) return;

            string error = string.Empty, errOriginal = string.Empty;
            if (result.Errors.Any())
            {
                errOriginal = result.Errors.First();
                error = errOriginal.ToLower();
            }

            if (string.IsNullOrWhiteSpace(error)) return;

            if (error.Contains("userid not found.") || error.Contains("userid cannot be found."))
                throw new UserNotExistException(errOriginal, ErrorCodes.UserIdNotFound);

            if (error.StartsWith("user") && error.EndsWith("does not exist."))
                throw new UserNotExistException(errOriginal, ErrorCodes.UserNameNotFound);

            if (error.StartsWith("email") && error.EndsWith("is already taken."))
                throw new InvalidUserInformationException(errOriginal, ErrorCodes.DuplicateEmail);

            if (error.StartsWith("email") && error.EndsWith("is invalid."))
                throw new InvalidUserInformationException(errOriginal, ErrorCodes.InvalidEmail);

            if ((error.StartsWith("name") || error.StartsWith("user name")) && error.EndsWith("is already taken."))
                throw new InvalidUserInformationException(errOriginal, ErrorCodes.DuplicateName);

            if (error.StartsWith("user name") && error.EndsWith("is invalid, can only contain letters or digits."))
                throw new InvalidUserInformationException(errOriginal, ErrorCodes.InvalidUserName);

            // for custom user validation  rule. Must start with user must
            if (error.StartsWith("user must"))
                throw new InvalidUserInformationException(error);


            if (error.Contains("incorrect password"))
                throw new InvalidPasswordException(errOriginal, ErrorCodes.PasswordMismatch);

            if (error.Contains("passwords must have at least one digit"))
                throw new InvalidPasswordException(errOriginal, ErrorCodes.PasswordRequireDigit);

            if (error.Contains("passwords must have at least one lowercase"))
                throw new InvalidPasswordException(errOriginal, ErrorCodes.PasswordRequireLower);

            if (error.Contains("passwords must have at least one non letter or digit character"))
                throw new InvalidPasswordException(errOriginal, ErrorCodes.PasswordRequireNonLetterOrDigit);

            if (error.Contains("passwords must have at least one uppercase"))
                throw new InvalidPasswordException(errOriginal, ErrorCodes.PasswordRequireUpper);

            if (error.StartsWith("passwords must be at least") && error.EndsWith("characters."))
                throw new InvalidPasswordException(errOriginal, ErrorCodes.PasswordTooShort);

            // for custom password rule. Must start with passwords must
            if (error.StartsWith("passwords must"))
                throw new InvalidPasswordException(errOriginal, ErrorCodes.PasswordIncorrect);


            if (error.Contains("invalid token"))
                throw new IdentityException(errOriginal, ErrorCodes.InvalidToken);

            if (error.StartsWith("no") && error.EndsWith("is registered."))
                throw new IdentityException(errOriginal, ErrorCodes.ComponentNotRegistered);

            if (error.StartsWith("store does not implement"))
                throw new IdentityException(errOriginal, ErrorCodes.StoreNotImplemented);


            if (error.StartsWith("role") && error.EndsWith("does not exist."))
                throw new RoleException(errOriginal, ErrorCodes.RoleNotFound);

            if (error.Contains("user already in role"))
                throw new RoleException(errOriginal, ErrorCodes.UserAlreadyInRole);

            if (error.Contains("user is not in role"))
                throw new RoleException(errOriginal, ErrorCodes.UserNotInRole);

            if (error.StartsWith("role"))
                throw new RoleException(errOriginal);

            // if not found with any specific exception, throw BaseIdentityException error and code unknown
            throw new IdentityException(errOriginal);
        }

        #endregion

        #endregion

        #region Private Function

        /// <summary>
        ///     Encrypt input data with DpAPI
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private string EncryptData(string data)
        {
            var ms = new MemoryStream();
            using (var writer = new StreamWriter(ms))
            {
                writer.Write(data);
            }

            var protectedBytes = _dataProtectorTokenProvider.Protector.Protect(ms.ToArray());
            return Convert.ToBase64String(protectedBytes);
        }

        /// <summary>
        ///     Decrypt provided data
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private string DecryptData(string data)
        {
            data = SanitizeToken(data);
            string output;
            var unprotectedData = _dataProtectorTokenProvider.Protector.Unprotect(Convert.FromBase64String(data));
            var ms = new MemoryStream(unprotectedData);
            using (var reader = new StreamReader(ms))
            {
                output = reader.ReadLine();
            }
            return output;
        }

        /// <summary>
        ///     Confirms the email and set password.
        /// </summary>
        /// <param name="code">The code.</param>
        /// <param name="token">The token.</param>
        /// <param name="password">The password.</param>
        /// <exception cref="Exception"></exception>
        private void ConfirmEmailAndSetPasswordInternal(string code, string token, string password)
        {
            Utils.EnsureNotNull(code, "code");
            Utils.EnsureNotNull(token, "token");

            var decodedCode = HttpUtility.UrlDecode(code);
            var decodedToken = SanitizeToken(HttpUtility.UrlDecode(token));
            var userId = Guid.Parse(DecryptData(decodedCode));

            using (var transaction = _dbContext.Database.BeginTransaction())
            {
                var user = ApplicationUserManager.FindById(userId);
                if (user == null)
                {
                    throw new UserNotExistException("Incorrect UserId from user token.", ErrorCodes.SecurityBreach);
                }

                user.IsActive = true;
                user.LastLoggedOn = DateTime.Now;
                user.LastModifiedOn = DateTime.Now;
                var result = ApplicationUserManager.Update(user);
                ProcessIdentityResult(result);

                result = ApplicationUserManager.ConfirmEmail(userId, decodedToken);
                ProcessIdentityResult(result);

                if (!string.IsNullOrWhiteSpace(password))
                {
                    if (user.PasswordHash != null)
                        throw new IdentityException("User  already has password.");

                    // add password will only work if already does not have any password
                    result = ApplicationUserManager.AddPassword(userId, password);
                    ProcessIdentityResult(result);
                }

                transaction.Commit();
            }
        }

        /// <summary>
        ///     Creates the application user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="userRoles">The user roles.</param>
        /// <param name="password">The password.</param>
        /// <exception cref="ArgumentNullException">user</exception>
        private void CreateAppUser(TUser user, IList<string> userRoles, string password)
        {
            Utils.EnsureNotNull(user, "user");

            using (var transaction = _dbContext.Database.BeginTransaction(IsolationLevel.ReadCommitted))
            {
                var result = string.IsNullOrWhiteSpace(password)
                    ? ApplicationUserManager.Create(user)
                    : ApplicationUserManager.Create(user, password);
                ProcessIdentityResult(result);

                if (userRoles != null && userRoles.Any())
                {
                    result = ApplicationUserManager.AddToRoles(user.Id, userRoles.ToArray());
                    ProcessIdentityResult(result);
                }
                transaction.Commit();
            }
        }

        /// <summary>
        ///     Sends the token email.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="token">The token.</param>
        /// <param name="callbackLink">The callback link.</param>
        /// <param name="templatePath">The template path.</param>
        /// <param name="subject">The subject.</param>
        /// <param name="additionalKeyTextList">The additional key text list to add in email body.</param>
        private void SendTokenEmail(Guid userId, string token, string callbackLink, string templatePath,
            string subject, List<KeyValuePair<string, string>> additionalKeyTextList = null)
        {
            var secureUserId = EncryptData(userId.ToString());
            var callbackUrl = string.Format(callbackLink, HttpUtility.UrlEncode(secureUserId),
                HttpUtility.UrlEncode(token));
            var emailTemplate = GetTemplatePath(templatePath);
            var mailbody = new StringBuilder(File.ReadAllText(emailTemplate));

            mailbody = mailbody.Replace("{link}", callbackUrl);

            // replace user defined keys with provided texts 
            if (additionalKeyTextList != null)
            {
                foreach (var pair in additionalKeyTextList)
                {
                    mailbody.Replace(pair.Key, pair.Value);
                }
            }
            ApplicationUserManager.SendEmail(userId, subject, mailbody.ToString());
        }

        /// <summary>
        ///     Gets the template path.
        /// </summary>
        /// <param name="templatePath">The template path.</param>
        /// <returns></returns>
        private static string GetTemplatePath(string templatePath)
        {
            string emailTemplate;
            if (HttpContext.Current != null)
            {
                emailTemplate = HttpContext.Current.Server.MapPath(string.Format("~/{0}", templatePath));
            }
            // for window applications
            else
            {
                var dir = AppDomain.CurrentDomain.BaseDirectory;
                emailTemplate = Path.Combine(dir, templatePath);
            }
            return emailTemplate;
        }

        /// <summary>
        ///     Updates the security stamp.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <returns></returns>
        public void UpdateSecurityStamp(Guid userId)
        {
            var result = ApplicationUserManager.UpdateSecurityStamp(userId);
            ProcessIdentityResult(result);
        }

        /// <summary>
        ///     Sanitize token got form user. Browser replace "+" with " " and we fix it here.
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        private string SanitizeToken(string token)
        {
            return token.Trim().Replace(" ", "+");
        }

        #region Constructor Support

        /// <summary>
        ///     Gets the user manager.
        /// </summary>
        /// <returns></returns>
        private UserManager<TUser, Guid> GetUserManager()
        {
            var manager = new UserManager<TUser, Guid>(new ApplicationUserStore<TUser>(_dbContext))
            {
                UserLockoutEnabledByDefault = true,
                DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(AppSettingsValueProvider.DefaultAccountLockoutTime),
                MaxFailedAccessAttemptsBeforeLockout = AppSettingsValueProvider.MaxFailedAccessAttemptsBeforeLockout
            };

            manager.RegisterTwoFactorProvider(IdentityConstants.EmailTwoFactorProviderName,
                new EmailTokenProvider<TUser, Guid>
                {
                    Subject = "SecurityCode",
                    BodyFormat = "Your security code is {0}"
                });

            return manager;
        }

        /// <summary>
        ///     Gets the default user validator.
        /// </summary>
        /// <param name="validator">The validator.</param>
        /// <returns></returns>
        private IIdentityValidator<TUser> GetDefaultUserValidator(Func<TUser, IEnumerable<string>> validator)
        {
            return new DefaultUserValidator<TUser>(ApplicationUserManager, validator)
            {
                AllowOnlyAlphanumericUserNames = AppSettingsValueProvider.AllowOnlyAlphanumericUserNames,
                RequireUniqueEmail = AppSettingsValueProvider.RequireUniqueEmail
            };
        }

        /// <summary>
        ///     Gets the default password validator.
        /// </summary>
        /// <returns></returns>
        private IIdentityValidator<string> GetDefaultPasswordValidator()
        {
            return new PasswordValidator
            {
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
                RequireNonLetterOrDigit = true,
                RequiredLength = 8
            };
        }

        /// <summary>
        ///     Gets the default user token provider.
        /// </summary>
        /// <returns></returns>
        private DataProtectorTokenProvider<TUser, Guid> GetDefaultUserTokenProvider()
        {
            var dpProtectionProvider = new MachineKeyProtectionProvider();
            return
                new DataProtectorTokenProvider<TUser, Guid>(dpProtectionProvider.Create(
                    AppSettingsValueProvider.AppName, AppSettingsValueProvider.AppSecret))
                {
                    TokenLifespan = TimeSpan.FromHours(AppSettingsValueProvider.TokenLifeTimeInHr)
                };
        }

        #endregion

        #endregion
    }
}