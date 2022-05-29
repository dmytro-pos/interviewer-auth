using InterviewerAPI.Interfaces.Repositories;
using InterviewerAPI.Models.AuthModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace InterviewerAPI.Controllers
{
    [ApiController]
    [Route("")]
    public class AuthController : ControllerBase
    {
        [HttpPost("authenticate")]
        public IActionResult AuthenticateUser([FromBody] UserLoginRequestModel userLoginModel,
            [FromServices] IAuthRepository authRepository)
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

        [HttpPost("refresh-token")]
        public IActionResult ExtendUserSession([FromBody] AuthenticationResponseModel extendUserSessionRequestModel,
            [FromServices] IAuthRepository authRepository)
        {
            try
            {
                var extendedTokens = authRepository.ExtendUserSession(extendUserSessionRequestModel);
                return Ok(extendedTokens);
            }
            catch (SecurityTokenException ex)
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