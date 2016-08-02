using System;

namespace CodeNode.Identity.Exceptions
{
    /// <summary>
    ///     BaseIdentityException
    /// </summary>
    [Serializable]
    public abstract class BaseIdentityException : Exception
    {
        /// <summary>
        ///     Initializes a new instance of the <see cref="BaseIdentityException" /> class.
        /// </summary>
        /// <param name="error">The error.</param>
        /// <param name="errorCode">The error code.</param>
        protected BaseIdentityException(string error, ErrorCodes errorCode = ErrorCodes.UnKnown)
            : base(error)
        {
            ErrorCode = errorCode;
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="BaseIdentityException" /> class.
        /// </summary>
        /// <param name="error">The error.</param>
        /// <param name="exception">The exception.</param>
        protected BaseIdentityException(string error, Exception exception)
            : base(error, exception)
        {
            ErrorCode = ErrorCodes.UnKnown;
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="BaseIdentityException" /> class.
        /// </summary>
        /// <param name="error">The error.</param>
        /// <param name="errorCode">The error code.</param>
        /// <param name="exception">The exception.</param>
        protected BaseIdentityException(string error, ErrorCodes errorCode, Exception exception)
            : this(error, exception)
        {
            ErrorCode = errorCode;
        }

        /// <summary>
        ///     Gets or sets the error code.
        /// </summary>
        /// <value>
        ///     The error code.
        /// </value>
        public ErrorCodes ErrorCode { get; protected set; }
    }
}