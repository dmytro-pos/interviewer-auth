using InterviewerAPI.Interfaces.Repositories;
using InterviewerAPI.Models.AuthModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Authentication;

namespace InterviewerAPI.Controllers
{
    [ApiController]
    [Route("[controller]/")]
    public class AuthController : ControllerBase
    {
        [HttpPost("token")]
        public IActionResult GetToken([FromBody] UserLoginModel userLoginModel, [FromServices] IAuthRepository authRepository)
        {
            try
            {
                var token = authRepository.GetToken(userLoginModel);
                return Ok(token);
            }
            catch (UnauthorizedAccessException ex) 
            {
                return Unauthorized(ex.Message);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }       
        }
    }
}