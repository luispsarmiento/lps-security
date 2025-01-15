using LPS.Security.API;
using IoCConfig;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

var builder = WebApplication.CreateBuilder(args);

string keyVaultName = Environment.GetEnvironmentVariable("KEY_VAULT_NAME");
var kvClient = new SecretClient(new Uri(keyVaultName),
    new DefaultAzureCredential());

// Add services to the container.
builder.Services.AddCustomOptions(builder.Configuration);
builder.Services.AddScoped<IUserContext, UserContext>();
builder.Services.AddCustomServices();
builder.Services.AddCustomJwtBearer(builder.Configuration, kvClient);
builder.Services.AddCustomCors();
builder.Services.AddCustomAutoMapper(typeof(Program));
builder.Services.AddControllers();
builder.Services.AddCustomSwagger();
//builder.Services.AddCustomCosmosDbService(builder.Configuration, kvClient);
builder.Services.AddCustomMongoDbService(builder.Configuration, kvClient);
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseSwagger();
app.UseSwaggerUI(c => { c.SwaggerEndpoint("/swagger/v1/swagger.json", "FShare API V1"); });

app.UseHttpsRedirection();
app.UseStatusCodePages();
app.UseRouting();
app.UseAuthentication();
app.UseCors("CorsPolicy");
app.UseAuthorization();

app.MapControllers();

app.Run();