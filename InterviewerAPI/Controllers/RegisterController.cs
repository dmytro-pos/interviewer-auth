using InterviewerAPI.Interfaces.Repositories;
using InterviewerAPI.Models.AuthModels;
using Microsoft.AspNetCore.Mvc;

namespace InterviewerAPI.Controllers
{
    [ApiController]
    [Route("[controller]/")]
    public class RegisterController : ControllerBase
    {
        [HttpPost("admin")]
        public IActionResult RegisterAdminAccount([FromBody] AdminAccountRegisterRequestModel adminAccountRegisterRequestModel,
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
