using System;

namespace JwtAuthService.Common.Models
{
	public class UserInstances
	{
		public UserInstances()
		{
		}

		public List<UserModel> Users = new List<UserModel>()
		{
			new UserModel() { Username = "coot", EmailAddress = "test_user@tester.com", FullName = "Test User", Password = "test_123", Role = "Admin"},

            new UserModel() { Username = "tommie", EmailAddress = "test_user2@tester.com", FullName = "Test User2", Password = "password124", Role = "contibutor"}
        };

		
	}
}

