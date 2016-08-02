using System;
using System.Configuration;
using System.Globalization;

namespace CodeNode.Identity.Utilities
{
    public class AppSettingsValueProvider
    {
        #region Variables

        private const string KeyNotFound = "Configuration key {0} is not found.";
        private const string KeyBlankValue = "Configuration key {0} has no value.";
        private const string KeyInvalidvalue = "Configuration key {0} has invalid value.";

        #endregion

        #region Properties

        #region App Security

        public static string AppName => GetConfigSetting<string>("AppName", true);

        public static int TokenLifeTimeInHr => GetConfigSetting<int>("TokenLifeTimeInHr", true);

        public static double OAuthTokenLifeTimeInHr => GetConfigSetting<double>("OAuthTokenLifeTimeInHr", true);

        public static bool EnableTwoFactorVerification => GetConfigSetting<bool>("EnableTwoFactorVerification", true);

        public static string TwoFactorHeaderName => GetConfigSetting<string>("TwoFactorHeaderName", true);

        public static string AppSecret => GetConfigSetting<string>("AppSecret", true);

        public static double AuthCookieLifeInHr => GetConfigSetting<double>("AuthCookieLifeInHr", true);

        public static bool AuthCookieSlidingExpiration => GetConfigSetting<bool>("AuthCookieSlidingExpiration", true);

        #endregion

        #region Templates and CallbackURLs

        public static string ResetPasswordMailSubject => GetConfigSetting<string>("ResetPasswordMailSubject", true);

        public static string ResetPasswordEmailTemplatePath
            => GetConfigSetting<string>("ResetPasswordTemplatePath", true);


        public static string ResetPasswordCallBackLink => GetConfigSetting<string>("ResetPasswordCallBackLink", true);

        public static string AccountActivationMailSubject
            => GetConfigSetting<string>("AccountActivationMailSubject", true);

        public static string AccountActivationTemplatePath
            => GetConfigSetting<string>("AccountActivationTemplatePath", true);

        public static string AccountActivationCallBackLink
            => GetConfigSetting<string>("AccountActivationCallBackLink", true);


        public static string EmailConfirmationTemplatePath
            => GetConfigSetting<string>("EmailConfirmationTemplatePath", true);

        public static string EmailConfirmationCallBackLink
            => GetConfigSetting<string>("EmailConfirmationCallBackLink", true);

        public static string EmailConfirmationMailSubject
            => GetConfigSetting<string>("EmailConfirmationMailSubject", true);

        #endregion

        #region Email Settings

        public static string Smtp => GetConfigSetting<string>("SMTP");

        public static int SmtpPort => GetConfigSetting<int>("SMTPPort");

        public static string SmtpSender => GetConfigSetting<string>("SMTPSender");

        public static string SenderDisplayName => GetConfigSetting<string>("SenderDisplayName");

        public static string SmtpSenderPassword => GetConfigSetting<string>("SMTPSenderPassword");

        public static bool EnableSsl => GetConfigSetting<bool>("EnableSsl");

        public static bool IsEmailBodyHtml => GetConfigSetting<bool>("IsEmailBodyHtml");

        #endregion

        #region User Configs

        public static int MaxFailedAccessAttemptsBeforeLockout
            => GetConfigSetting<int>("MaxFailedAccessAttemptsBeforeLockout", true);

        public static bool ShouldLockOutAccount => GetConfigSetting<bool>("ShouldLockOutAccount", true);

        public static int DefaultAccountLockoutTime
            => GetConfigSetting<int>("DefaultAccountLockoutTimeSpanInMins", true);

        public static bool AllowOnlyAlphanumericUserNames
            => GetConfigSetting<bool>("AllowOnlyAlphanumericUserNames", true);

        public static bool RequireUniqueEmail => GetConfigSetting<bool>("RequireUniqueEmail", true);

        #endregion

        #endregion

        #region Private Methods

        protected static T GetConfigSetting<T>(string configKey)
        {
            return GetConfigSetting<T>(configKey, false);
        }

        protected static T GetConfigSetting<T>(string configKey, bool mustNotBeBlank)
        {
            var configValue = ConfigurationManager.AppSettings[configKey];

            if (configValue == null)
                //// Throw exception if config. setting is not found.
                throw new ConfigurationErrorsException(string.Format(KeyNotFound, configKey));

            if (mustNotBeBlank && string.IsNullOrWhiteSpace(configValue))
                //// Throw exception if config. setting is found but its value is blank.
                throw new ConfigurationErrorsException(string.Format(KeyBlankValue, configKey));

            T result;
            try
            {
                result = (T) Convert.ChangeType(configValue, typeof(T), CultureInfo.InvariantCulture);
            }
            catch (Exception ex)
            {
                //// Throw exception if config. setting's value cannot be converted to desired data type.
                throw new ConfigurationErrorsException(string.Format(KeyInvalidvalue, configKey), ex);
            }

            return result;
        }

        #endregion
    }
}