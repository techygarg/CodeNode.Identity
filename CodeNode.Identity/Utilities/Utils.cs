using System;

namespace CodeNode.Identity.Utilities
{
    public static class Utils
    {
        /// <summary>
        ///     Ensures the not null.
        /// </summary>
        /// <param name="item">The item.</param>
        /// <param name="message">The message.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void EnsureNotNull(Guid item, string message)
        {
            if (item == null || Guid.Empty.Equals(item))
            {
                throw new ArgumentNullException(message);
            }
        }

        /// <summary>
        ///     Ensures the not null.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="item">The item.</param>
        /// <param name="message">The message.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void EnsureNotNull<T>(T item, string message) where T : class
        {
            if (item == null)
            {
                throw new ArgumentNullException(message);
            }
        }

        /// <summary>
        ///     Ensures the not null.
        /// </summary>
        /// <param name="item">The item.</param>
        /// <param name="message">The message.</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void EnsureNotNull(string item, string message)
        {
            if (string.IsNullOrWhiteSpace(item))
            {
                throw new ArgumentNullException(message);
            }
        }
    }
}