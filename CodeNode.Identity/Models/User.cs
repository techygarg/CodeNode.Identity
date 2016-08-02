using System;
using System.Collections.Generic;

namespace UserManagment
{
    public class User
    {
        /// <summary>
        ///     Initializes a new instance of the <see cref="User" /> class.
        /// </summary>
        public User()
        {
            Roles = new List<Role>();
        }

        /// <summary>
        ///     Gets or sets the user identifier.
        /// </summary>
        /// <value>
        ///     The user identifier.
        /// </value>
        public Guid UserId { get; set; }

        /// <summary>
        ///     Gets or sets the name of the user.
        /// </summary>
        /// <value>
        ///     The name of the user.
        /// </value>
        public string UserName { get; set; }

        /// <summary>
        ///     Gets or sets the password.
        /// </summary>
        /// <value>
        ///     The password.
        /// </value>
        public string Password { get; set; }

        /// <summary>
        ///     Gets or sets the salutation.
        /// </summary>
        /// <value>
        ///     The salutation.
        /// </value>
        public string Salutation { get; set; }

        /// <summary>
        ///     Gets or sets the first name.
        /// </summary>
        /// <value>
        ///     The first name.
        /// </value>
        public string FirstName { get; set; }

        /// <summary>
        ///     Gets or sets the last name.
        /// </summary>
        /// <value>
        ///     The last name.
        /// </value>
        public string LastName { get; set; }

        /// <summary>
        ///     Gets or sets the address.
        /// </summary>
        /// <value>
        ///     The address.
        /// </value>
        public string Address { get; set; }

        /// <summary>
        ///     Gets or sets the email.
        /// </summary>
        /// <value>
        ///     The email.
        /// </value>
        public string Email { get; set; }

        /// <summary>
        ///     Gets or sets the email confirmed.
        /// </summary>
        /// <value>
        ///     The email confirmed.
        /// </value>
        public bool EmailConfirmed { get; set; }

        /// <summary>
        ///     Gets or sets the phone number.
        /// </summary>
        /// <value>
        ///     The phone number.
        /// </value>
        public string PhoneNumber { get; set; }

        /// <summary>
        ///     Gets or sets the phone number confirmed.
        /// </summary>
        /// <value>
        ///     The phone number confirmed.
        /// </value>
        public bool PhoneNumberConfirmed { get; set; }

        /// <summary>
        ///     Gets or sets the lockout en date UTC.
        /// </summary>
        /// <value>
        ///     The lockout en date UTC.
        /// </value>
        public DateTime? LockoutEnDateUTC { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether [lockout enabled].
        /// </summary>
        /// <value>
        ///     <c>true</c> if [lockout enabled]; otherwise, <c>false</c>.
        /// </value>
        public bool LockoutEnabled { get; set; }

        /// <summary>
        ///     Gets or sets the access failed count.
        /// </summary>
        /// <value>
        ///     The access failed count.
        /// </value>
        public int AccessFailedCount { get; set; }

        /// <summary>
        ///     Gets or sets the roles.
        /// </summary>
        /// <value>
        ///     The roles.
        /// </value>
        public IList<Role> Roles { get; set; }

        /// <summary>
        ///     Gets or sets the is first login.
        /// </summary>
        /// <value>
        ///     The is first login.
        /// </value>
        public bool IsFirstLogin { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether this instance is active.
        /// </summary>
        /// <value>
        ///     <c>true</c> if this instance is active; otherwise, <c>false</c>.
        /// </value>
        public bool IsActive { get; set; }

        /// <summary>
        ///     Gets or sets the other properties.
        /// </summary>
        /// <value>
        ///     The other properties.
        /// </value>
        public string OtherProperties { get; set; }

        /// <summary>
        ///     Gets or sets the created by.
        /// </summary>
        /// <value>
        ///     The created by.
        /// </value>
        public Guid CreatedBy { get; set; }

        /// <summary>
        ///     Gets or sets the created on.
        /// </summary>
        /// <value>
        ///     The created on.
        /// </value>
        public DateTime CreatedOn { get; set; }

        /// <summary>
        ///     Gets or sets the last modified by.
        /// </summary>
        /// <value>
        ///     The last modified by.
        /// </value>
        public Guid? LastModifiedBy { get; set; }

        /// <summary>
        ///     Gets or sets the last modified on.
        /// </summary>
        /// <value>
        ///     The last modified on.
        /// </value>
        public DateTime? LastModifiedOn { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether this instance is default account.
        /// </summary>
        /// <value>
        ///     <c>true</c> if this instance is default account; otherwise, <c>false</c>.
        /// </value>
        public bool IsDefaultAccount { get; set; }

        public DateTime? LastLoggedOn { get; set; }
    }
}