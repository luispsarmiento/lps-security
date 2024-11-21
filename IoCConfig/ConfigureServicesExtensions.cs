﻿using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Azure.Cosmos;
using DataAccess;
using Domain.Repositories;
using Domain.Services;
using Service;
using Microsoft.EntityFrameworkCore;
using Domain.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.OpenApi.Models;
using AutoMapper;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace IoCConfig
{
    public static class ConfigureServicesExtensions
    {
		public static void AddCustomCors(this IServiceCollection services)
		{
			services.AddCors(options =>
			options.AddPolicy("CorsPolicy",
			builder => builder
				.WithOrigins("http://localhost:7157")
				.AllowAnyMethod()
				.AllowAnyHeader()
				.SetIsOriginAllowed((host) => true)
				.AllowCredentials()
			));
		}

		public static void AddCustomJwtBearer(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddAuthorization(options =>
			{
				options.AddPolicy(CustomRoles.Admin, policy => policy.RequireRole(CustomRoles.Admin));
				options.AddPolicy(CustomRoles.User, policy => policy.RequireRole(CustomRoles.User));
			});

			services.AddAuthentication(options =>
			{
				options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
				options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
			})
			.AddJwtBearer(configureOptions =>
			{
				configureOptions.RequireHttpsMetadata = false;
				configureOptions.SaveToken = true;
				configureOptions.TokenValidationParameters = new TokenValidationParameters
				{
					ValidIssuer = configuration["Jwt:Issuer"],
					ValidateIssuer = true,
					ValidAudience = configuration["Jwt:Audience"],
					ValidateAudience = true,
					IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"])),
					ValidateIssuerSigningKey = true,
					ValidateLifetime = true,
					ClockSkew = TimeSpan.Zero
				};
				configureOptions.Events = new JwtBearerEvents
				{
					OnTokenValidated = context =>
					{
						IJwtTokenService jwtTokenService = context.HttpContext.RequestServices.GetRequiredService<IJwtTokenService>();
						return jwtTokenService.ValidateAsync(context);
					}
				};
			});
		}
		public static void AddCustomServices(this IServiceCollection services)
        {
			services.AddScoped<IJwtTokenService, JwtTokenService>();
			services.AddScoped<IUserRepository, UserRepository>();
			services.AddScoped<ISecurityService, SecurityService>();
			services.AddScoped<IUserService, UserService>();
			services.AddHttpContextAccessor();
		}
		public static void AddCustomOptions(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddOptions<JwtOptions>().Bind(configuration.GetSection("Jwt"));
		}
		public static void AddCustomSwagger(this IServiceCollection services)
		{

			services.AddSwaggerGen(options =>
			{
				options.SwaggerDoc("v1", new OpenApiInfo
				{
					Title = "LPS Security API Document",
					Version = "v1"
				});

				options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
				{
					Description = @"JWT Authorization header using the Bearer scheme. \r\n\r\n 
						Enter 'Bearer' [space] and then your token in the text input below.
						\r\n\r\nExample: 'Bearer 12345abcdef'",
					Name = "Authorization",
					In = ParameterLocation.Header,
					Type = SecuritySchemeType.ApiKey,
					Scheme = "Bearer"
				});

				options.AddSecurityRequirement(new OpenApiSecurityRequirement()
				{
					{
						new OpenApiSecurityScheme
						{
								Reference = new OpenApiReference
								{
										Type = ReferenceType.SecurityScheme,
										Id = "Bearer"
								},
								Scheme = "oauth2",
								Name = "Bearer",
								In = ParameterLocation.Header,

						},
						new List<string>()
					}
				});
			});
		}
		public static void AddCustomCosmosDbService(this IServiceCollection services, IConfiguration configuration)
        {
            /*services.AddDbContext<CosmosDbContext>(options =>
            {
                var configurationSection = configuration.GetSection("CosmosDb");
                options.UseCosmos(configurationSection["Account"], configurationSection["Key"], configurationSection["DatabaseName"]);
            });*/

			services.AddDbContext<LPSSecurityDbContext>(optionsBuilder => optionsBuilder
					/*** Implemented LoggerFactory to get query information to CosmosBD ***/
					.EnableSensitiveDataLogging()//Los datos sensibles quedan expuestos, habilitar esto si hay una medida de seguridad
					.UseLoggerFactory(LoggerFactory.Create(builder =>
						builder.AddConsole()
							   .AddFilter(string.Empty, LogLevel.Information)// Just Information, to not full the logger
					))
					.ConfigureWarnings(builder => 
						builder.Log((CoreEventId.QueryCompilationStarting, LogLevel.Information))// Le decimos que las consultas las vea como una advertencia
							   .Ignore(new[] { CosmosEventId.ExecutingSqlQuery })// ya que tenemos el evento que se activa despues de un query, es necesario ignorar el registro del inicio de un query
                               .Throw(new[] { CoreEventId.FirstWithoutOrderByAndFilterWarning })// indicamos que se lance un warning si una query usar First whithout OrderBy
					)
					.UseCosmos(
						connectionString: configuration.GetSection("CosmosDB")["ConnectionString"],
						databaseName: configuration.GetSection("CosmosDB")["DatabaseName"],
						cosmosOptionsAction: options =>
						{
							options.ConnectionMode(ConnectionMode.Direct);
							options.MaxRequestsPerTcpConnection(20);
							options.MaxTcpConnectionsPerEndpoint(32);
						}
					));
		}

		public static void AddCustomAutoMapper(this IServiceCollection services, Type type)
        {
			services.AddAutoMapper(type);
			services.AddControllersWithViews();
		}
    }
}