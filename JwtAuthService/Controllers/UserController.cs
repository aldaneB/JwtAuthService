using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using JwtAuthService.Common.Models;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JwtAuthService.webapi.Controllers
{
    /// <summary>
    /// This controller will be used to create token and Authenticate user
    /// </summary>
    /// 
    [Route("api/[controller]")]
    public class UserController : Controller
    {
        //Used to access configuration files
        private readonly IConfiguration _configuration;

        public UserController(IConfiguration _configuration)
        {
            this._configuration = _configuration;
        }

        //Allows the user to access method without having to be Authenticated
        [AllowAnonymous]
        [HttpPost]
        [Route("login")]
        public IActionResult Login([FromBody] UserDto login)
        {
            //Authenticate User Login Information
            var user = AuthenticateUser(login);

            //If the user is authenticated, Generate Token from User Model Instance
            if (user != null)
            {
                var token = GenerateToken(user);
                return Ok(token);
            }

            return NotFound("User Name or Password is Wrong!");
        }

        /// <summary>
        /// Generate a user token as a string from UserModel Instance 
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        private string GenerateToken(UserModel user)
        {
            //Create a new Symmetric Security Key using JWT security key
            //from config file
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetRequiredSection("Jwt:Key").Value));

            //Define Credentials Object using security key and HmacSha256
            //security algorithm
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            //Define UserModel Parameters in JWT Claims to be serialized in token
            var claims = new[]
            {
               new Claim(ClaimTypes.NameIdentifier, user.Username),
               new Claim(ClaimTypes.Email, user.EmailAddress),
               new Claim(ClaimTypes.GivenName, user.FullName),
               new Claim(ClaimTypes.Role, user.Role)
            };

            //Creates new Jwt Security Token that expires after 15 mins
            var token = new JwtSecurityToken(
               _configuration.GetRequiredSection("Jwt:Issuer").Value,
               _configuration.GetRequiredSection("Jwt:Audience").Value,
               claims,
               expires: DateTime.Now.AddMinutes(15),
               signingCredentials: credentials
               );

            //Serializes JWT into a compact format
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        /// <summary>
        /// Returns an Authenticated User Model 
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        private UserModel? AuthenticateUser(UserDto login)
        {
            //Create Instance of UserInstances
            UserInstances userInstance = new UserInstances();

            //[Could Identify Current User Using HttpContext]
            //Gets Current User by checking against Login Information
            var currentUser = userInstance.Users.FirstOrDefault(o => o.Username.ToLower() == login.Username.ToLower
            () && o.Password == login.Password);

            //If User Exist, returns current user model
            if (currentUser != null)
            {
                return currentUser;
            }

            return null;
        }

        [HttpGet("Admin")]
        [Authorize]
        //[Route("Public")]
        public IActionResult Admin()
        {
           var currentUser = GetCurrentUser();
            return Ok($"Current Logged in user {currentUser?.FullName} with role of an {currentUser?.Role}");
        }


        private UserModel? GetCurrentUser()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;

            if (identity != null)
            {
                var userClaims = identity.Claims;

                return new UserModel
                {
                    Username = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.NameIdentifier).Value,
                    EmailAddress = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Email).Value,
                    FullName = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.GivenName).Value,
                    Role = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Role).Value,
                };
            } 
            return null;
        }
    }
}

