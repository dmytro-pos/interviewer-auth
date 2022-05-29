using InterviewerAPI.Interfaces.Repositories;
using InterviewerAPI.Models.AuthModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace InterviewerAPI.Controllers
{
    [ApiController]
    [Route("[controller]/")]
    public class RegisterController : ControllerBase
    {

        [HttpGet("owner")]
        [Authorize(Roles = "Owner")]
        public IActionResult GetToken()
        {
            return Ok("You're owner");
        }

        [HttpGet("adminAndOwner")]
        [Authorize(Roles = "Owner, Admin")]
        public IActionResult GetTokesn()
        {
            return Ok("Owner: " + User.IsInRole("Owner").ToString() + " " + "Admin: " + User.IsInRole("Admin").ToString());
        }

        [HttpPost("admin")]
        public IActionResult GetToken([FromBody] AdminAccountRegisterRequestModel adminAccountRegisterRequestModel,
            [FromServices] IRegisterRepository registerRepository)
        {
            try
            {
                registerRepository.RegisterAdministratorAccount(adminAccountRegisterRequestModel);
                return Ok("User was succesfully created");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
