using InterviewerAPI.Interfaces.Repositories;
using InterviewerAPI.Models.AuthModels;
using Microsoft.AspNetCore.Mvc;

namespace InterviewerAPI.Controllers
{
    [ApiController]
    [Route("")]
    public class AuthController : ControllerBase
    {
        [HttpPost("authenticate")]
        public IActionResult AuthenticateUser([FromBody] UserLoginRequestModel userLoginModel, [FromServices] IAuthRepository authRepository)
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