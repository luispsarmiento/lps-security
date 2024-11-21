using Domain.Repositories;
using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.Cosmos;
using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;

namespace DataAccess
{
    public class BaseRepository<T> : IBaseRepository<T> where T : BaseEntity
    {
        public readonly LPSSecurityDbContext _context;
        public BaseRepository(LPSSecurityDbContext cosmosDbContext)
        {
            _context = cosmosDbContext;
            _context.Database.EnsureCreated();
        }
        public virtual async Task<T> Add(T entity)
        {
            try
            {
                var result = await _context.Set<T>().AddAsync(entity);

                await _context.SaveChangesAsync();

                return result.Entity;
            }
            catch(Exception)
            {
                throw;
            }
        }

        public virtual async Task Delete(T entity)
        {
            _context.Set<T>().Remove(entity);
            await _context.SaveChangesAsync();
        }

        public virtual async Task<IEnumerable<T>> Find(Expression<Func<T, bool>> predicate)
        {
            return await _context.Set<T>().Where(predicate).ToListAsync();
        }

        public virtual async Task<T> Update(T entity)
        {
            try
            {
                var result = _context.Set<T>().Update(entity);

                _context.Entry(entity).State = EntityState.Modified;

                await Complete();

                return result.Entity;
            }
            catch (Exception)
            {
                throw;
            }
        }

        protected async Task Complete()
        {
            //******************************************************************************************************************
            //
            // This was take from:
            // https://github.com/JurgenOnAzure/ef-core-6-using-azure-cosmos-db/blob/main/M5%20Concurrency/1.%20Using%20ETag/TransportApp.Service/TransportService.cs
            // if you desire know click above link
            //
            //******************************************************************************************************************
            var wasSaved = false;
            var sanityCounter = 0;

            while ( !wasSaved && ++sanityCounter <= 10 )
            {
                try
                {
                    await _context.SaveChangesAsync();

                    wasSaved = true;
                }
                catch (DbUpdateConcurrencyException ex)
                {
                    var entry = ex.Entries[0];

                    var databaseValues = await entry.GetDatabaseValuesAsync();
                    //******************************************************************************************************************
                    //var proposedValues = entry.CurrentValues;

                    //foreach (var property in proposedValues.Properties
                    //  .Where(property => property.Name != "__jObject"
                    //    && !property.IsConcurrencyToken))
                    //{
                    //    var propertyName = property.Name;
                    //    var databaseValue = databaseValues[property];
                    //    var proposedValue = proposedValues[property];

                    //    if (!object.Equals(databaseValue, proposedValue))
                    //    {
                    //        writeLine($"    '{propertyName}': original = {databaseValue}, proposed = {proposedValue}");
                    //    }
                    //}
                    // We can do more here like save the conflict to Log
                    //var mustSaveConflictingEntity = true; // TODO: apply your custom logic here

                    //if (!mustSaveConflictingEntity)
                    //{
                    //    // nothing to do
                    //    break;
                    //}
                    //******************************************************************************************************************

                    // skip next concurrency check
                    entry.OriginalValues.SetValues(databaseValues);
                }
            }

            if( !wasSaved )
            {
                throw new Exception($"Conflictinh entity was not saved");
            }
        }
    }
}
