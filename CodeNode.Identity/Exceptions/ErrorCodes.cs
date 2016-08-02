namespace CodeNode.Identity.Exceptions
{
    public enum ErrorCodes
    {
        UnKnown = 0,

        UserIdNotFound = 1,
        UserNameNotFound = 2,
        UserEmailNotFound = 3,

        DuplicateEmail = 4,
        DuplicateName = 5,
        InvalidUserName = 6,
        InvalidEmail = 7,

        PasswordIncorrect = 8,
        PasswordMismatch = 9,
        PasswordRequireDigit = 10,
        PasswordRequireLower = 11,
        PasswordRequireNonLetterOrDigit = 12,
        PasswordRequireUpper = 13,
        PasswordTooShort = 14,

        InvalidToken = 15,
        ComponentNotRegistered = 16,
        StoreNotImplemented = 17,
        UserNotActive = 18,

        RoleNotExist = 19,
        RoleAlreadyExist = 20,
        RoleNotFound = 21,
        UserAlreadyInRole = 22,
        UserNotInRole = 23,

        SecurityBreach = 23,
        CurrentUserNotFound = 24
    }
}